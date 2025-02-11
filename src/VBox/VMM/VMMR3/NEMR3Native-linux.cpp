/* $Id: NEMR3Native-linux.cpp $ */
/** @file
 * NEM - Native execution manager, native ring-3 Linux backend.
 */

/*
 * Copyright (C) 2021-2024 Oracle and/or its affiliates.
 *
 * This file is part of VirtualBox base platform packages, as
 * available from https://www.virtualbox.org.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, in version 3 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses>.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/
#define LOG_GROUP LOG_GROUP_NEM
#define VMCPU_INCL_CPUM_GST_CTX
#include <VBox/vmm/nem.h>
#include <VBox/vmm/iem.h>
#include <VBox/vmm/em.h>
#include <VBox/vmm/apic.h>
#include <VBox/vmm/pdm.h>
#include <VBox/vmm/trpm.h>
#include "CPUMInternal.h"
#include "NEMInternal.h"
#include "HMInternal.h"
#include "GIMInternal.h"
#include "GIMHvInternal.h"
#include <VBox/vmm/vmcc.h>

#include <iprt/alloca.h>
#include <iprt/mem.h>
#include <iprt/string.h>
#include <iprt/system.h>
#include <iprt/x86.h>

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/kvm.h>

/* Forward declarations of things called by the template. */
static int nemR3LnxInitSetupVm(PVM pVM, PRTERRINFO pErrInfo);
#include <algorithm>
#include <string_view>
#include <vector>

/**
 * The MMIO address of the TPR register of the LAPIC.
 */
static constexpr uint64_t XAPIC_TPR_ADDR {0xfee00080};

/* Instantiate the common bits we share with the ARMv8 KVM backend. */
#include "NEMR3NativeTemplate-linux.cpp.h"

/**
 * The class priority shift for the TPR register.
 */
static constexpr uint64_t LAPIC_TPR_SHIFT {4};

#ifdef VBOX_WITH_KVM_IRQCHIP_FULL
static int kvmSetGsiRoutingFullIrqChip(PVM pVM);
#endif



#ifdef VBOX_WITH_KVM_NESTING
static int KvmGetGuestModeOffsetFromStatsFd(PVMCPU pVCpu, size_t *offset)
{
    // See https://www.kernel.org/doc/html/latest/virt/kvm/api.html to learn more
    // about the KVM binary statistics (look for KVM_GET_STATS_FD).

    struct kvm_stats_header stats_header;
    RT_ZERO(stats_header);

    int rcRead = pread(pVCpu->nem.s.statsFd, &stats_header, sizeof(struct kvm_stats_header), 0);
    AssertReleaseMsg(rcRead == sizeof(struct kvm_stats_header), ("Unable to read stats header"));

    if (offset == nullptr) {
        printf("Invalid pointer\n");
        return VERR_INVALID_POINTER;
    }

    int real_desc_size = sizeof(struct kvm_stats_desc) + stats_header.name_size;
    void *desc_backing = RTMemAllocZ(real_desc_size);

    int rc = VERR_NOT_IMPLEMENTED;

    for (unsigned i = 0; i < stats_header.num_desc; ++i) {
        memset(desc_backing, 0, real_desc_size);

        struct kvm_stats_desc* desc = static_cast<struct kvm_stats_desc*>(desc_backing);
        rcRead = pread(pVCpu->nem.s.statsFd, desc, real_desc_size, stats_header.desc_offset + i * real_desc_size);
        AssertReleaseMsg(rcRead == real_desc_size, ("Unable to read descriptor"));

        std::basic_string_view name(desc->name);
        if (name == "guest_mode") {
            unsigned value_offset = stats_header.data_offset + desc->offset;

            if (desc->size != 1) {
                LogRel(("Invalid guest_mode stat size: %d\n", desc->size * 8));
                rc = VERR_NOT_SUPPORTED;
                break;
            }

            *offset = value_offset;

            rc = VINF_SUCCESS;
            break;
        }
    }

    RTMemFree(desc_backing);
    return rc;
}
#endif

bool KvmIsNestedGuestExit(PVM pVM, PVMCPU pVCpu)
{
#ifdef VBOX_WITH_KVM_NESTING
    if (not pVM->cpum.s.GuestFeatures.fVmx) {
        return false;
    }

    uint64_t value {0};

    AssertReleaseMsg(pVCpu->nem.s.guestModeStatOffset != 0, ("Invalid guest_mode offset"));

    int rcRead = pread(pVCpu->nem.s.statsFd, &value, 8, pVCpu->nem.s.guestModeStatOffset);
    AssertReleaseMsg(rcRead == 8, ("pread did not read all bytes: %d\n", rcRead));

    return value != 0;
#else
    NOREF(pVM); NOREF(pVCpu);
    return false;
#endif
}

/**
 * Does the early setup of a KVM VM.
 *
 * @returns VBox status code.
 * @param   pVM                 The cross context VM structure.
 * @param   pErrInfo            Where to always return error info.
 */
static int nemR3LnxInitSetupVm(PVM pVM, PRTERRINFO pErrInfo)
{
    AssertReturn(pVM->nem.s.fdVm != -1, RTErrInfoSet(pErrInfo, VERR_WRONG_ORDER, "Wrong initalization order"));

    /*
     * Enable user space MSRs and let us check everything KVM cannot handle.
     * We will set up filtering later when ring-3 init has completed.
     */
    struct kvm_enable_cap CapEn =
    {
        KVM_CAP_X86_USER_SPACE_MSR, 0,
        { KVM_MSR_EXIT_REASON_FILTER | KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_INVAL, 0, 0, 0}
    };
    int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_ENABLE_CAP, &CapEn);
    if (rcLnx == -1)
        return RTErrInfoSetF(pErrInfo, VERR_NEM_VM_CREATE_FAILED, "Failed to enable KVM_CAP_X86_USER_SPACE_MSR failed: %u", errno);

#ifdef VBOX_WITH_KVM_IRQCHIP_FULL
    rcLnx = ioctl(pVM->nem.s.fdVm, KVM_CREATE_IRQCHIP, 0);
    if (rcLnx == -1)
        return RTErrInfoSetF(pErrInfo, VERR_NEM_VM_CREATE_FAILED, "Failed to execute KVM_CREATE_VCPU: %u", errno);

    kvmSetGsiRoutingFullIrqChip(pVM);
#else
    struct kvm_enable_cap CapSplitIrqChip =
    {
        KVM_CAP_SPLIT_IRQCHIP, 0,
        { KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS, 0, 0, 0}
    };
    rcLnx = ioctl(pVM->nem.s.fdVm, KVM_ENABLE_CAP, &CapSplitIrqChip);
    if (rcLnx == -1)
        return RTErrInfoSetF(pErrInfo, VERR_NEM_VM_CREATE_FAILED, "Failed to enable KVM_CAP_SPLIT_IRQCHIP: %u", errno);
#endif

    /*
     * Create the VCpus.
     */
    for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
    {
        PVMCPU pVCpu = pVM->apCpusR3[idCpu];

        /* Create it. */
        pVCpu->nem.s.fdVCpu = ioctl(pVM->nem.s.fdVm, KVM_CREATE_VCPU, (unsigned long)idCpu);
        if (pVCpu->nem.s.fdVCpu < 0)
            return RTErrInfoSetF(pErrInfo, VERR_NEM_VM_CREATE_FAILED, "KVM_CREATE_VCPU failed for VCpu #%u: %d", idCpu, errno);

        /* Map the KVM_RUN area. */
        pVCpu->nem.s.pRun = (struct kvm_run *)mmap(NULL, pVM->nem.s.cbVCpuMmap, PROT_READ | PROT_WRITE, MAP_SHARED,
                                                   pVCpu->nem.s.fdVCpu, 0 /*offset*/);
        if ((void *)pVCpu->nem.s.pRun == MAP_FAILED)
            return RTErrInfoSetF(pErrInfo, VERR_NEM_VM_CREATE_FAILED, "mmap failed for VCpu #%u: %d", idCpu, errno);

        /* We want all x86 registers and events on each exit. */
        pVCpu->nem.s.pRun->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;

#ifdef VBOX_WITH_KVM_NESTING
        pVCpu->nem.s.statsFd = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_STATS_FD, 0);

        if (pVCpu->nem.s.statsFd < 0) {
            return RTErrInfoSetF(pErrInfo, VERR_NEM_VM_CREATE_FAILED, "Failed to get stats FD");
        }

        int rc = KvmGetGuestModeOffsetFromStatsFd(pVCpu, &pVCpu->nem.s.guestModeStatOffset);
        if (not RT_SUCCESS(rc)) {
            // Instead of failing here, we could also de-feature nested hardware virtualization.
            return RTErrInfoSetF(pErrInfo, VERR_NEM_VM_CREATE_FAILED, "Failed to get guest_mode offset");
        }

        if (idCpu == 0) {
            // Log the offset once, just for debugging purposes.
            LogRel2(("KVM: guest_mode offset is at %d\n", pVCpu->nem.s.guestModeStatOffset));
        }
#endif
    }

    pVM->nem.s.pARedirectionTable = std::make_unique<std::array<std::optional<MSIMSG>, KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS>>();

    return VINF_SUCCESS;
}

static void nemR3LnxConsumePokeSignal()
{
    int iPokeSignal = RTThreadPokeSignal();
    AssertReturnVoid(iPokeSignal >= 0);

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, iPokeSignal);

    struct timespec timeout;

    /* Don't wait for a signal, just poll. */
    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;

    int rc = sigtimedwait(&sigset, nullptr, &timeout);
    AssertLogRelMsg(rc >= 0 || errno == EAGAIN || errno == EINTR, ("Failed to consume signal: %d", errno));
}

static PCPUMCPUIDLEAF findKvmLeaf(PCPUMCPUIDLEAF paKvmSupportedLeaves,
                                  uint32_t cKvmSupportedLeaves,
                                  uint32_t leaf,
                                  uint32_t subleaf)
{
    for (uint32_t i = 0; i < cKvmSupportedLeaves; i++) {
        auto& kvmLeaf = paKvmSupportedLeaves[i];

        if (kvmLeaf.uLeaf == leaf && kvmLeaf.uSubLeaf == subleaf) {
            return &kvmLeaf;
        }
    }

    return nullptr;
}

static void maybeMaskUnsupportedKVMCpuidLeafValues(PCPUMCPUIDLEAF paKvmSupportedLeaves,
                                                   uint32_t cKvmSupportedLeaves,
                                                   uint32_t leaf,
                                                   uint32_t subleaf,
                                                   uint32_t& eax,
                                                   uint32_t& ebx,
                                                   uint32_t& ecx,
                                                   uint32_t& edx)
{
    static const uint32_t CPUID_FEATURE_INFORMATION_LEAF = 0x1;

    /*
     * A list of CPUID leaves that we want to mask with the KVM
     * supported values. For example, we want to make sure that FSGSBASE
     * support is supported by KVM before we offer it to the guest.
     * VirtualBox detects the features it wants to offer via CPUID,
     * which bypasses Linux/KVM.
     */
    const std::vector<uint32_t> leavesToMask = {
        CPUID_FEATURE_INFORMATION_LEAF,
        0x6,        // Thermal and power management
        0x7,        // Structured Extended Feature Flags Enumeration
        0x12,       // SGX capabilities
        0x14,       // Processor Trace
        0x19,       // AES Key Locker features
        0x24,       // AVX10 Features
        0x80000001, // Extended Processor Info and Feature Bits
        0x80000007, // Processor Power Management Information and RAS Capabilities
        0x80000008, // Virtual and Physical address Sizes
        0x8000000A, // Secure Virtual Machine features
        0x8000001F, // Encrypted Memory Capabilities
        0x80000021, // Extended Feature Identification 2
    };

    if (std::find(leavesToMask.begin(), leavesToMask.end(), leaf) == leavesToMask.end()) {
        return;
    }

    auto* paKvmSupportedLeaf = findKvmLeaf(paKvmSupportedLeaves, cKvmSupportedLeaves, leaf, subleaf);

    if (paKvmSupportedLeaf == nullptr) {
        return;
    }

    switch (leaf) {
    case CPUID_FEATURE_INFORMATION_LEAF:
        eax &= paKvmSupportedLeaf->uEax;
        // ebx reports APIC IDs which we would mask if we use the
        // KVM supported values.
        ecx &= paKvmSupportedLeaf->uEcx;
        ecx |= X86_CPUID_FEATURE_ECX_HVP; // The hypervisor bit is not enabled in the KVM values.
        edx &= paKvmSupportedLeaf->uEdx;
        break;
    default:
        eax &= paKvmSupportedLeaf->uEax;
        ebx &= paKvmSupportedLeaf->uEbx;
        ecx &= paKvmSupportedLeaf->uEcx;
        edx &= paKvmSupportedLeaf->uEdx;
        break;
    }
}

/**
 * Update the CPUID leaves for a VCPU.
 *
 * The KVM_SET_CPUID2 call replaces any previous leaves, so we have to redo
 * everything when there really just are single bit changes.  That said, it
 * looks like KVM update the XCR/XSAVE related stuff as well as the APIC enabled
 * bit(s), so it should suffice if we do this at startup, I hope.
 */
static int nemR3LnxUpdateCpuIdsLeaves(PVM pVM, PVMCPU pVCpu)
{
    uint32_t              cLeaves  = 0;
    PCCPUMCPUIDLEAF const paLeaves = CPUMR3CpuIdGetPtr(pVM, &cLeaves);
    struct kvm_cpuid2    *pReq = (struct kvm_cpuid2 *)alloca(RT_UOFFSETOF_DYN(struct kvm_cpuid2, entries[cLeaves + 2]));

    pReq->nent    = cLeaves;
    pReq->padding = 0;

    size_t cKvmSupportedLeaves = 0;
    PCPUMCPUIDLEAF paKvmSupportedLeaves = nullptr;
    int rc = NEMR3KvmGetCpuIdLeaves(pVM, &paKvmSupportedLeaves, &cKvmSupportedLeaves);
    AssertLogRelMsgReturn(RT_SUCCESS(rc), ("Could not retrieve supported CPUID leaves"), rc);


    for (uint32_t i = 0; i < cLeaves; i++)
    {
        CPUMGetGuestCpuId(pVCpu, paLeaves[i].uLeaf, paLeaves[i].uSubLeaf, -1 /*f64BitMode*/,
                          &pReq->entries[i].eax,
                          &pReq->entries[i].ebx,
                          &pReq->entries[i].ecx,
                          &pReq->entries[i].edx);

        maybeMaskUnsupportedKVMCpuidLeafValues(paKvmSupportedLeaves,
                                               cKvmSupportedLeaves,
                                               paLeaves[i].uLeaf,
                                               paLeaves[i].uSubLeaf,
                                               pReq->entries[i].eax,
                                               pReq->entries[i].ebx,
                                               pReq->entries[i].ecx,
                                               pReq->entries[i].edx);

        pReq->entries[i].function   = paLeaves[i].uLeaf;
        pReq->entries[i].index      = paLeaves[i].uSubLeaf;
        pReq->entries[i].flags      = !paLeaves[i].fSubLeafMask ? 0 : KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
        pReq->entries[i].padding[0] = 0;
        pReq->entries[i].padding[1] = 0;
        pReq->entries[i].padding[2] = 0;
    }

    int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_CPUID2, pReq);
    AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d cLeaves=%#x\n", rcLnx, errno, cLeaves), RTErrConvertFromErrno(errno));

    return VINF_SUCCESS;
}

static int nemR3LnxInitGuestInterface(PVM pVM)
{
    switch (pVM->gim.s.enmProviderId) {
    case GIMPROVIDERID_HYPERV:
        /*
          SynIC is currently disabled pending investigation of interrupt issues. See #19.

          Enabling this capability is not sufficient to enable SynNIC. The corresponding features in the Hyper-V CPUID
          leaves also have to be enabled. Look for SYNIC and STIMER in GIMHv.cpp.

          The CPUID implementation hints must also indicate deprecating AutoEOI to make APICv work.
         */
#if 1
        LogRel(("NEM: Enabling SYNIC.\n"));

        for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
        {
            PVMCPU pVCpu = pVM->apCpusR3[idCpu];

            struct kvm_enable_cap CapSynIC =
            {
                KVM_CAP_HYPERV_SYNIC2, 0, { 0, 0, 0, 0 }
            };

            int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_ENABLE_CAP, &CapSynIC);
            AssertLogRelMsgReturn(rcLnx == 0, ("Failed to enable SYNIC: rcLnx=%d errno=%d\n", rcLnx, errno),
                                  RTErrConvertFromErrno(errno));
        }
#endif

        break;

    default:
        /* Other guest interfaces are not fully supported. */
        break;
    }

    return VINF_SUCCESS;
}

namespace
{

enum class KvmCpuIdIoctl : uint32_t
{
    CPUID = KVM_GET_SUPPORTED_CPUID,
    HV_CPUID = KVM_GET_SUPPORTED_HV_CPUID
};

int KvmGetCpuIdLeavesGeneric(PVM pVM, KvmCpuIdIoctl ioctlNum, PCPUMCPUIDLEAF *outpCpuId, size_t *outcLeaves)
{
    struct kvm_cpuid2 *pKvmCpuid;
    uint32_t cLeaves = 0;
    int rc;

    /* In case we exit due to errors. */
    *outpCpuId = nullptr;
    *outcLeaves = 0;

    /* There is no way to query how many leaves there are. We just try until we hit the right size. */
    do
    {
        cLeaves += 1;
        Log(("Querying for %u leaves\n", cLeaves));

        pKvmCpuid = static_cast<struct kvm_cpuid2 *>(alloca(RT_UOFFSETOF_DYN(struct kvm_cpuid2, entries[cLeaves])));

        pKvmCpuid->nent = cLeaves;
        pKvmCpuid->padding = 0;

        rc = ioctl(pVM->nem.s.fdKvm, static_cast<uint32_t>(ioctlNum), pKvmCpuid);
    } while (rc != 0 && errno == E2BIG);
    AssertLogRelMsgReturn(rc == 0, ("Failed to query supported CPUID leaves: errno=%d", errno), RTErrConvertFromErrno(errno));
    AssertFatal(cLeaves == pKvmCpuid->nent);

    PCPUMCPUIDLEAF pCpuId = static_cast<PCPUMCPUIDLEAF>(RTMemAllocZ(sizeof(*pCpuId) * cLeaves));

    for (uint32_t uLeaf = 0; uLeaf < cLeaves; uLeaf++)
    {
        pCpuId[uLeaf].uLeaf = pKvmCpuid->entries[uLeaf].function;
        pCpuId[uLeaf].uSubLeaf = pKvmCpuid->entries[uLeaf].index;

        pCpuId[uLeaf].uEax = pKvmCpuid->entries[uLeaf].eax;
        pCpuId[uLeaf].uEbx = pKvmCpuid->entries[uLeaf].ebx;
        pCpuId[uLeaf].uEcx = pKvmCpuid->entries[uLeaf].ecx;
        pCpuId[uLeaf].uEdx = pKvmCpuid->entries[uLeaf].edx;
    }

    *outpCpuId = pCpuId;
    *outcLeaves = cLeaves;

    return VINF_SUCCESS;
}

} // anonymous namespace

int NEMR3KvmGetHvCpuIdLeaves(PVM pVM, PCPUMCPUIDLEAF *outpCpuId, size_t *outcLeaves)
{
    return KvmGetCpuIdLeavesGeneric(pVM, KvmCpuIdIoctl::HV_CPUID, outpCpuId, outcLeaves);
}

int NEMR3KvmGetCpuIdLeaves(PVM pVM, PCPUMCPUIDLEAF *outpCpuId, size_t *outcLeaves)
{
    return KvmGetCpuIdLeavesGeneric(pVM, KvmCpuIdIoctl::CPUID, outpCpuId, outcLeaves);
}

int nemR3NativeInitCompleted(PVM pVM, VMINITCOMPLETED enmWhat)
{
    /*
     * Make RTThreadPoke work again (disabled for avoiding unnecessary
     * critical section issues in ring-0).
     */
    if (enmWhat == VMINITCOMPLETED_RING3)
        VMMR3EmtRendezvous(pVM, VMMEMTRENDEZVOUS_FLAGS_TYPE_ALL_AT_ONCE, nemR3LnxFixThreadPoke, NULL);

    /*
     * Configure CPUIDs after ring-3 init has been done.
     */
    if (enmWhat == VMINITCOMPLETED_RING3)
    {
        for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
        {
            PCPUMCTXMSRS const  pCtxMsrs    = CPUMQueryGuestCtxMsrsPtr(pVM->apCpusR3[idCpu]);

            int rc = nemR3LnxUpdateCpuIdsLeaves(pVM, pVM->apCpusR3[idCpu]);
            AssertRCReturn(rc, rc);

#ifdef VBOX_WITH_KVM_NESTING
            if (pVM->cpum.s.GuestFeatures.fVmx) {
                NEMR3KvmSetMsr(pVM->apCpusR3[idCpu], MSR_IA32_FEATURE_CONTROL, MSR_IA32_FEATURE_CONTROL_VMXON | MSR_IA32_FEATURE_CONTROL_LOCK);
            }
#endif

            uint64_t val {0};
            NEMR3KvmGetMsr(pVM->apCpusR3[idCpu], MSR_IA32_ARCH_CAPABILITIES, &val);
            pCtxMsrs->msr.ArchCaps = val;

            NEMR3KvmGetMsr(pVM->apCpusR3[idCpu], MSR_IA32_SPEC_CTRL, &val);
            pCtxMsrs->msr.SpecCtrl = val;
        }
    }

    if (enmWhat == VMINITCOMPLETED_RING3)
    {
        int rc = nemR3LnxInitGuestInterface(pVM);
        AssertRCReturn(rc, rc);
    }

    /*
     * Configure MSRs after ring-3 init is done.
     *
     * We only need to tell KVM which MSRs it can handle, as we already
     * requested KVM_MSR_EXIT_REASON_FILTER, KVM_MSR_EXIT_REASON_UNKNOWN
     * and KVM_MSR_EXIT_REASON_INVAL in nemR3LnxInitSetupVm, and here we
     * will use KVM_MSR_FILTER_DEFAULT_DENY.  So, all MSRs w/o a 1 in the
     * bitmaps should be deferred to ring-3.
     */
    if (enmWhat == VMINITCOMPLETED_RING3)
    {
        struct kvm_msr_filter MsrFilters = {0}; /* Structure with a couple of implicit paddings on 64-bit systems. */
        MsrFilters.flags = KVM_MSR_FILTER_DEFAULT_DENY;

        unsigned iRange = 0;
#define MSR_RANGE_BEGIN(a_uBase, a_uEnd, a_fFlags) \
        AssertCompile(0x3000 <= KVM_MSR_FILTER_MAX_BITMAP_SIZE * 8); \
        uint64_t RT_CONCAT(bm, a_uBase)[0x3000 / 64] = {0}; \
        do { \
            uint64_t * const pbm = RT_CONCAT(bm, a_uBase); \
            uint32_t   const uBase = UINT32_C(a_uBase); \
            uint32_t   const cMsrs = UINT32_C(a_uEnd) - UINT32_C(a_uBase); \
            MsrFilters.ranges[iRange].base   = UINT32_C(a_uBase); \
            MsrFilters.ranges[iRange].nmsrs  = cMsrs; \
            MsrFilters.ranges[iRange].flags  = (a_fFlags); \
            MsrFilters.ranges[iRange].bitmap = (uint8_t *)&RT_CONCAT(bm, a_uBase)[0]
#define MSR_RANGE_ADD(a_Msr) \
        do { Assert((uint32_t)(a_Msr) - uBase < cMsrs); ASMBitSet(pbm, (uint32_t)(a_Msr) - uBase); } while (0)
#define MSR_RANGE_ADD_CLOSED_IVL(first_Msr, last_Msr) \
        for (uint32_t uMsr = (first_Msr); uMsr <= last_Msr; uMsr++) { MSR_RANGE_ADD(uMsr); }
#define MSR_RANGE_END(a_cMinMsrs) \
            /* optimize the range size before closing: */ \
            uint32_t cBitmap = cMsrs / 64; \
            while (cBitmap > ((a_cMinMsrs) + 63 / 64) && pbm[cBitmap - 1] == 0) \
                cBitmap -= 1; \
            MsrFilters.ranges[iRange].nmsrs = cBitmap * 64; \
            iRange++; \
        } while (0)

        /* 1st Intel range: 0000_0000 to 0000_3000. */
        MSR_RANGE_BEGIN(0x00000000, 0x00003000, KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);
        MSR_RANGE_ADD(MSR_IA32_BIOS_SIGN_ID);
        MSR_RANGE_ADD(MSR_IA32_TSC);
        MSR_RANGE_ADD(MSR_IA32_APICBASE);
        MSR_RANGE_ADD(MSR_IA32_SYSENTER_CS);
        MSR_RANGE_ADD(MSR_IA32_SYSENTER_ESP);
        MSR_RANGE_ADD(MSR_IA32_SYSENTER_EIP);
        MSR_RANGE_ADD(MSR_IA32_CR_PAT);
        MSR_RANGE_ADD(MSR_IA32_ARCH_CAPABILITIES);
        MSR_RANGE_ADD(MSR_IA32_SPEC_CTRL);
        MSR_RANGE_ADD(MSR_IA32_PRED_CMD);
        MSR_RANGE_ADD(MSR_IA32_FLUSH_CMD);

#ifdef VBOX_WITH_KVM_NESTING
        if (pVM->cpum.s.GuestFeatures.fVmx) {
            /* VMX MSRS */
            MSR_RANGE_ADD(MSR_IA32_FEATURE_CONTROL);
            MSR_RANGE_ADD(MSR_IA32_MISC_ENABLE);
            MSR_RANGE_ADD(MSR_IA32_VMX_BASIC);
            MSR_RANGE_ADD(MSR_IA32_VMX_PINBASED_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_PROCBASED_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_EXIT_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_ENTRY_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_MISC);
            MSR_RANGE_ADD(MSR_IA32_VMX_CR0_FIXED0);
            MSR_RANGE_ADD(MSR_IA32_VMX_CR0_FIXED1);
            MSR_RANGE_ADD(MSR_IA32_VMX_CR4_FIXED0);
            MSR_RANGE_ADD(MSR_IA32_VMX_CR4_FIXED1);
            MSR_RANGE_ADD(MSR_IA32_VMX_VMCS_ENUM);
            MSR_RANGE_ADD(MSR_IA32_VMX_PROCBASED_CTLS2);
            MSR_RANGE_ADD(MSR_IA32_VMX_EPT_VPID_CAP);
            MSR_RANGE_ADD(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_TRUE_EXIT_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
            MSR_RANGE_ADD(MSR_IA32_VMX_VMFUNC);
            MSR_RANGE_ADD(MSR_IA32_VMX_PROCBASED_CTLS3);
            MSR_RANGE_ADD(MSR_IA32_VMX_EXIT_CTLS2);
        }
#endif
        /** @todo more? */
        MSR_RANGE_END(64);

        /* 1st AMD range: c000_0000 to c000_3000 */
        MSR_RANGE_BEGIN(0xc0000000, 0xc0003000, KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);
        MSR_RANGE_ADD(MSR_K6_EFER);
        MSR_RANGE_ADD(MSR_K6_STAR);

        /*
         * If we don't allow direct access to FS_BASE, we clobber the FS base for the guest. This sounds like a bug in
         * our state synchronization with KVM.
         */
        MSR_RANGE_ADD(MSR_K8_FS_BASE);

        MSR_RANGE_ADD(MSR_K8_GS_BASE);
        MSR_RANGE_ADD(MSR_K8_KERNEL_GS_BASE);
        MSR_RANGE_ADD(MSR_K8_LSTAR);
        MSR_RANGE_ADD(MSR_K8_CSTAR);
        MSR_RANGE_ADD(MSR_K8_SF_MASK);
        MSR_RANGE_ADD(MSR_K8_TSC_AUX);
        /** @todo add more? */
        MSR_RANGE_END(64);

        if (pVM->gim.s.enmProviderId == GIMPROVIDERID_HYPERV)
        {
            MSR_RANGE_BEGIN(0x40000000, 0x40003000, KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE);

            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE0_FIRST, MSR_GIM_HV_RANGE0_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE1_FIRST, MSR_GIM_HV_RANGE1_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE2_FIRST, MSR_GIM_HV_RANGE2_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE3_FIRST, MSR_GIM_HV_RANGE3_LAST);

            /* SynIC / STimer */
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE4_FIRST, MSR_GIM_HV_RANGE4_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE5_FIRST, MSR_GIM_HV_RANGE5_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE6_FIRST, MSR_GIM_HV_RANGE6_LAST);

            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE7_FIRST, MSR_GIM_HV_RANGE7_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE8_FIRST, MSR_GIM_HV_RANGE8_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE9_FIRST, MSR_GIM_HV_RANGE9_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE10_FIRST, MSR_GIM_HV_RANGE10_LAST);
            MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE11_FIRST, MSR_GIM_HV_RANGE11_LAST);

            /*
             * Crash MSRs
             *
             * We deliberately don't add them here, so we can handle them instead of KVM. This allows us to log the
             * crash reason into VM log instead of it ending up in the kernel's log.
             */
            // MSR_RANGE_ADD_CLOSED_IVL(MSR_GIM_HV_RANGE12_FIRST, MSR_GIM_HV_RANGE12_LAST);

            /*
             * These should be available to the guest with feature bit 23 in the base features, which we don't
             * expose. But Windows touches them anyway?
             */
            MSR_RANGE_ADD(0x40000114 /* HV_X64_MSR_STIME_UNHALTED_TIMER_CONFIG */);
            MSR_RANGE_ADD(0x40000115 /* HV_X64_MSR_STIME_UNHALTED_TIMER_COUNT */);

            /*
             * These are available to the guest with feature bit 15 in the base features (undocumented).
             */
            MSR_RANGE_ADD(0x40000118 /* HV_X64_MSR_TSC_INVARIANT_CONTROL */);

            MSR_RANGE_END(64);
        }

        /** @todo Specify other ranges too? Like hyper-V and KVM to make sure we get
         *        the MSR requests instead of KVM. */

        int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_X86_SET_MSR_FILTER, &MsrFilters);
        if (rcLnx == -1)
            return VMSetError(pVM, VERR_NEM_VM_CREATE_FAILED, RT_SRC_POS,
                              "Failed to enable KVM_X86_SET_MSR_FILTER failed: %u", errno);
    }

    return VINF_SUCCESS;
}



/*********************************************************************************************************************************
*   Memory management                                                                                                            *
*********************************************************************************************************************************/

VMMR3_INT_DECL(int) NEMR3LoadExec(PVM pVM)
{
    // TODO: this code leaves a small window between the guest sending an INIT IPI
    // and a subsequent SIPI IPI. If that's the case, we need to set the MP state
    // `KVM_MP_STATE_INIT_RECEIVED` which requires some serious interaction
    // between the NEM and SSM. For now, we hope that noone suspends a VM during
    // VCPU bringup. See vbox-engineering#426.
    for (VMCPUID i = 0; i < pVM->cCpus; i++) {
        PVMCPU pVCpu = pVM->apCpusR3[i];
        auto state = VMCPU_GET_STATE(pVCpu);
        if (state == VMCPUSTATE_STARTED || state == VMCPUSTATE_STARTED_EXEC_NEM || state == VMCPUSTATE_STARTED_EXEC_NEM_WAIT )
        {
            struct kvm_mp_state mp;
            mp.mp_state = KVM_MP_STATE_RUNNABLE;
            int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_MP_STATE, &mp);
            AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3Load: Failed to set MP state. Error: %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);
        }
    }
    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmGetMsr(PVMCPU pVCpu, uint64_t msr, uint64_t* val)
{
    alignas(struct kvm_msrs) char backing[sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)];
    struct kvm_msrs* msr_data {reinterpret_cast<struct kvm_msrs*>(&backing[0])};
    RT_ZERO(backing);

    msr_data->nmsrs = 1;
    msr_data->entries[0].index = msr;

    int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_MSRS, msr_data);
    AssertLogRelMsgReturn(rcLnx == 1, ("NEMR3KvmGetMsr: \
                Failed to get MSR data. Error: %d, errno %d\n", rcLnx, errno), VERR_NOT_SUPPORTED);

    AssertLogRelMsgReturn(val != nullptr, ("NEMR3KvmGetMsr: \
                Invalid buffer\n", rcLnx, errno), VERR_NEM_IPE_5);

    *val = msr_data->entries[0].data;

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmSetMsr(PVMCPU pVCpu, uint64_t msr, uint64_t val)
{
    alignas(struct kvm_msrs) char backing[sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)];
    struct kvm_msrs* msr_data {reinterpret_cast<struct kvm_msrs*>(&backing[0])};
    RT_ZERO(backing);

    msr_data->nmsrs = 1;
    msr_data->entries[0].index = msr;
    msr_data->entries[0].data = val;

    int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_MSRS, msr_data);
    AssertLogRelMsgReturn(rcLnx == 1, ("NEMR3KvmSetMsr: \
                Failed to set MSR[%lx] data. Error: %d, errno %d\n", msr, rcLnx, errno), VERR_NOT_SUPPORTED);

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmGetLapicState(PVMCPU pVCpu, void* pXApicPage)
{
    struct kvm_lapic_state state;

    int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_LAPIC, &state);
    AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3KvmGetLapicState: \
                Failed to get APIC state. Error: %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);

    memcpy(pXApicPage, &state.regs[0], KVM_APIC_REG_SIZE);
    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmSetLapicState(PVMCPU pVCpu, void* pXApicPage)
{
    struct kvm_lapic_state state;

    memcpy(&state.regs[0], pXApicPage, KVM_APIC_REG_SIZE);

    int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_LAPIC, &state);
    AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3KvmSetApicState: \
                Failed to set APIC state. Error %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmSetIrqLine(PVM pVM, uint16_t u16Gsi, int iLevel)
{
    struct kvm_irq_level irq;
    RT_ZERO(irq);

    irq.irq = u16Gsi;
    irq.level = iLevel;

    int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_IRQ_LINE, &irq);
    AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3KvmSetIrqLine: Failed to set irq line %d! error: %d, errno %d\n", u16Gsi, rcLnx, errno), VERR_NEM_IPE_5);

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmSplitIrqchipDeliverMsi(PVM pVM, PCMSIMSG pMsi)
{
    AssertLogRelReturn(pVM != nullptr, VERR_INVALID_POINTER);
    AssertLogRelReturn(pMsi != nullptr, VERR_INVALID_POINTER);

    struct kvm_msi msi;
    RT_ZERO(msi);
    msi.address_lo = pMsi->Addr.au32[0];
    msi.address_hi = pMsi->Addr.au32[1];
    msi.data = pMsi->Data.u32;

    int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_SIGNAL_MSI, &msi);
    AssertLogRelMsgReturn(rcLnx >= 0, ("NEMR3KvmSplitIrqchipDeliverMsi: Failed to deliver MSI! error: %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);

    return rcLnx == 0 ? VERR_APIC_INTR_DISCARDED : VINF_SUCCESS;
}

#ifdef VBOX_WITH_KVM_IRQCHIP_FULL
static int kvmSetGsiRoutingFullIrqChip(PVM pVM)
{
    alignas(kvm_irq_routing) char backing[ sizeof(struct kvm_irq_routing) +
        (KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS + KVM_IRQCHIP_NUM_PIC_INTR_PINS) * sizeof(struct kvm_irq_routing_entry) ] {};
    kvm_irq_routing* routing = reinterpret_cast<kvm_irq_routing*>(backing);

    for (unsigned i = 0; i < KVM_IRQCHIP_NUM_PIC_INTR_PINS; ++i) {
        routing->entries[i].gsi = i;
        routing->entries[i].type = KVM_IRQ_ROUTING_IRQCHIP;
        routing->entries[i].u.irqchip.irqchip = (i < 8) ? KVM_IRQCHIP_PIC_MASTER : KVM_IRQCHIP_PIC_SLAVE;
        routing->entries[i].u.irqchip.pin = (i < 8) ? i : (i - 8);
    }

    for (unsigned i = 0; i < KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS; ++i) {
        uint64_t arr_idx = i + KVM_IRQCHIP_NUM_PIC_INTR_PINS;
        routing->entries[arr_idx].gsi = i;
        routing->entries[arr_idx].type = KVM_IRQ_ROUTING_IRQCHIP;
        routing->entries[arr_idx].u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
        if (i == 0) {
            routing->entries[arr_idx].u.irqchip.pin = 2;
        } else {
            routing->entries[arr_idx].u.irqchip.pin = i;
        }
    }
    routing->nr = KVM_IRQCHIP_NUM_PIC_INTR_PINS + KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS;

    int rc = ioctl(pVM->nem.s.fdVm, KVM_SET_GSI_ROUTING, routing);

    AssertLogRelMsgReturn(rc >= 0, ("NEM/KVM: Unable to set GSI routing! rc: %d errno %d \n", rc, errno), VERR_INTERNAL_ERROR);

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmGetPicState(PVM pVM, KVMIRQCHIP irqchip, KVMPICSTATE* state)
{
    struct kvm_irqchip irqchip_state;
    irqchip_state.chip_id = irqchip == KVMIRQCHIP::PIC_MASTER ? KVM_IRQCHIP_PIC_MASTER : KVM_IRQCHIP_PIC_SLAVE;

    if (state == nullptr) {
        return VERR_INVALID_POINTER;
    }

    int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_GET_IRQCHIP, &irqchip_state);
    AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3KvmGetPicState: \
                Failed to get PIC state. Error: %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);

    state->last_irr = irqchip_state.chip.pic.last_irr;
    state->irr = irqchip_state.chip.pic.irr;
    state->imr = irqchip_state.chip.pic.imr;
    state->isr = irqchip_state.chip.pic.isr;
    state->priority_add = irqchip_state.chip.pic.priority_add;
    state->irq_base = irqchip_state.chip.pic.irq_base;
    state->read_reg_select = irqchip_state.chip.pic.read_reg_select;
    state->poll = irqchip_state.chip.pic.poll;
    state->special_mask = irqchip_state.chip.pic.special_mask;
    state->init_state = irqchip_state.chip.pic.init_state;
    state->auto_eoi = irqchip_state.chip.pic.auto_eoi;
    state->rotate_on_auto_eoi = irqchip_state.chip.pic.rotate_on_auto_eoi;
    state->special_fully_nested_mode = irqchip_state.chip.pic.special_fully_nested_mode;
    state->init4 = irqchip_state.chip.pic.init4;
    state->elcr = irqchip_state.chip.pic.elcr;
    state->elcr_mask = irqchip_state.chip.pic.elcr_mask;

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmSetPicState(PVM pVM, KVMIRQCHIP irqchip, KVMPICSTATE* state)
{
    struct kvm_irqchip irqchip_state;
    irqchip_state.chip_id = irqchip == KVMIRQCHIP::PIC_MASTER ? KVM_IRQCHIP_PIC_MASTER : KVM_IRQCHIP_PIC_SLAVE;

    if (state == nullptr) {
        return VERR_INVALID_POINTER;
    }

    irqchip_state.chip.pic.last_irr = state->last_irr;
    irqchip_state.chip.pic.irr = state->irr;
    irqchip_state.chip.pic.imr = state->imr;
    irqchip_state.chip.pic.isr = state->isr;
    irqchip_state.chip.pic.priority_add = state->priority_add;
    irqchip_state.chip.pic.irq_base = state->irq_base;
    irqchip_state.chip.pic.read_reg_select = state->read_reg_select;
    irqchip_state.chip.pic.poll = state->poll;
    irqchip_state.chip.pic.special_mask = state->special_mask;
    irqchip_state.chip.pic.init_state = state->init_state;
    irqchip_state.chip.pic.auto_eoi = state->auto_eoi;
    irqchip_state.chip.pic.rotate_on_auto_eoi = state->rotate_on_auto_eoi;
    irqchip_state.chip.pic.special_fully_nested_mode = state->special_fully_nested_mode;
    irqchip_state.chip.pic.init4 = state->init4;
    irqchip_state.chip.pic.elcr = state->elcr;
    irqchip_state.chip.pic.elcr_mask = state->elcr_mask;

    int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_GET_IRQCHIP, &irqchip_state);
    AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3KvmSetPicState: \
                Failed to get PIC state. Error: %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmGetIoApicState(PVM pVM, KVMIOAPICSTATE* state)
{
    struct kvm_irqchip irqchip_state;
    irqchip_state.chip_id = KVM_IRQCHIP_IOAPIC;

    if (state == nullptr) {
        return VERR_INVALID_POINTER;
    }

    int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_GET_IRQCHIP, &irqchip_state);
    AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3KvmGetIoApicState: \
                Failed to get IOAPIC state. Error: %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);

    state->base_address = irqchip_state.chip.ioapic.base_address;
    state->ioregsel = irqchip_state.chip.ioapic.ioregsel;
    state->id = irqchip_state.chip.ioapic.id;
    state->irr = irqchip_state.chip.ioapic.irr;

    for (unsigned i = 0; i < KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS; ++i) {
        state->redirtbl[i] = irqchip_state.chip.ioapic.redirtbl[i].bits;
    }

    return VINF_SUCCESS;
}

VMMR3_INT_DECL(int) NEMR3KvmSetIoApicState(PVM pVM, KVMIOAPICSTATE* state)
{
    struct kvm_irqchip irqchip_state;
    irqchip_state.chip_id = KVM_IRQCHIP_IOAPIC;

    if (state == nullptr) {
        return VERR_INVALID_POINTER;
    }

    irqchip_state.chip.ioapic.base_address = state->base_address;
    irqchip_state.chip.ioapic.ioregsel = state->ioregsel;
    irqchip_state.chip.ioapic.id = state->id;
    irqchip_state.chip.ioapic.irr = state->irr;

    for (unsigned i = 0; i < KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS; ++i) {
        irqchip_state.chip.ioapic.redirtbl[i].bits = state->redirtbl[i];
    }

    int rcLnx = ioctl(pVM->nem.s.fdVm, KVM_SET_IRQCHIP, &irqchip_state);
    AssertLogRelMsgReturn(rcLnx == 0, ("NEMR3KvmSetIoApicState: \
                Failed to set IOPIC state. Error: %d, errno %d\n", rcLnx, errno), VERR_NEM_IPE_5);

    return VINF_SUCCESS;
}
#endif

static int kvmSetGsiRouting(PVM pVM)
{
    alignas(kvm_irq_routing) char backing[ sizeof(struct kvm_irq_routing) + KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS * sizeof(struct kvm_irq_routing_entry) ] {};
    kvm_irq_routing* routing = reinterpret_cast<kvm_irq_routing*>(backing);

    unsigned routingCount {0};

    for(unsigned i {0}; i < KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS; ++i)
    {
        if (pVM->nem.s.pARedirectionTable->at(i).has_value())
        {
            PMSIMSG msi = &(pVM->nem.s.pARedirectionTable->at(i).value());
            routing->entries[routingCount].gsi = i;
            routing->entries[routingCount].type = KVM_IRQ_ROUTING_MSI;
            routing->entries[routingCount].u.msi.address_lo = msi->Addr.au32[0];
            routing->entries[routingCount].u.msi.address_hi = msi->Addr.au32[1];
            routing->entries[routingCount].u.msi.data = msi->Data.u32;
            routingCount++;
        }
    }

    routing->nr = routingCount;

    int rc = ioctl(pVM->nem.s.fdVm, KVM_SET_GSI_ROUTING, routing);

    AssertLogRelMsgReturn(rc >= 0, ("NEM/KVM: Unable to set GSI routing! rc: %d errno %d \n", rc, errno), VERR_INTERNAL_ERROR);

    return VINF_SUCCESS;
}


VMMR3_INT_DECL(int) NEMR3KvmSplitIrqchipAddUpdateRTE(PVM pVM, uint16_t u16Gsi, PCMSIMSG pMsi)
{
    AssertRelease(pVM->nem.s.pARedirectionTable != nullptr);
    AssertRelease(u16Gsi < KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS);

    pVM->nem.s.pARedirectionTable->at(u16Gsi) = *pMsi;

    return kvmSetGsiRouting(pVM);
}


VMMR3_INT_DECL(int) NEMR3KvmSplitIrqchipRemoveRTE(PVM pVM, uint16_t u16Gsi)
{
    AssertRelease(pVM->nem.s.pARedirectionTable != nullptr);
    AssertRelease(u16Gsi < KVM_IRQCHIP_NUM_IOAPIC_INTR_PINS);

    pVM->nem.s.pARedirectionTable->at(u16Gsi) = std::nullopt;

    return kvmSetGsiRouting(pVM);
}


/*********************************************************************************************************************************
*   CPU State                                                                                                                    *
*********************************************************************************************************************************/

/**
 * Worker that imports selected state from KVM.
 */
static int nemHCLnxImportState(PVMCPUCC pVCpu, uint64_t fWhat, PCPUMCTX pCtx, struct kvm_run *pRun)
{
    fWhat &= pVCpu->cpum.GstCtx.fExtrn;
    if (!fWhat)
        return VINF_SUCCESS;

    /*
     * Stuff that goes into kvm_run::s.regs.regs:
     */
    if (fWhat & (CPUMCTX_EXTRN_RIP | CPUMCTX_EXTRN_RFLAGS | CPUMCTX_EXTRN_GPRS_MASK))
    {
        if (fWhat & CPUMCTX_EXTRN_RIP)
            pCtx->rip       = pRun->s.regs.regs.rip;
        if (fWhat & CPUMCTX_EXTRN_RFLAGS)
            pCtx->rflags.u  = pRun->s.regs.regs.rflags;

        if (fWhat & CPUMCTX_EXTRN_RAX)
            pCtx->rax       = pRun->s.regs.regs.rax;
        if (fWhat & CPUMCTX_EXTRN_RCX)
            pCtx->rcx       = pRun->s.regs.regs.rcx;
        if (fWhat & CPUMCTX_EXTRN_RDX)
            pCtx->rdx       = pRun->s.regs.regs.rdx;
        if (fWhat & CPUMCTX_EXTRN_RBX)
            pCtx->rbx       = pRun->s.regs.regs.rbx;
        if (fWhat & CPUMCTX_EXTRN_RSP)
            pCtx->rsp       = pRun->s.regs.regs.rsp;
        if (fWhat & CPUMCTX_EXTRN_RBP)
            pCtx->rbp       = pRun->s.regs.regs.rbp;
        if (fWhat & CPUMCTX_EXTRN_RSI)
            pCtx->rsi       = pRun->s.regs.regs.rsi;
        if (fWhat & CPUMCTX_EXTRN_RDI)
            pCtx->rdi       = pRun->s.regs.regs.rdi;
        if (fWhat & CPUMCTX_EXTRN_R8_R15)
        {
            pCtx->r8        = pRun->s.regs.regs.r8;
            pCtx->r9        = pRun->s.regs.regs.r9;
            pCtx->r10       = pRun->s.regs.regs.r10;
            pCtx->r11       = pRun->s.regs.regs.r11;
            pCtx->r12       = pRun->s.regs.regs.r12;
            pCtx->r13       = pRun->s.regs.regs.r13;
            pCtx->r14       = pRun->s.regs.regs.r14;
            pCtx->r15       = pRun->s.regs.regs.r15;
        }
    }

    /*
     * Stuff that goes into kvm_run::s.regs.sregs.
     *
     * Note! The apic_base can be ignored because we gets all MSR writes to it
     *       and VBox always keeps the correct value.
     */
    bool fMaybeChangedMode = false;
    bool fUpdateCr3        = false;
    if (fWhat & (  CPUMCTX_EXTRN_SREG_MASK | CPUMCTX_EXTRN_TABLE_MASK | CPUMCTX_EXTRN_CR_MASK
                 | CPUMCTX_EXTRN_EFER      | CPUMCTX_EXTRN_APIC_TPR))
    {
        /** @todo what about Attr.n.u4LimitHigh?   */
#define NEM_LNX_IMPORT_SEG(a_CtxSeg, a_KvmSeg) do { \
            (a_CtxSeg).u64Base              = (a_KvmSeg).base; \
            (a_CtxSeg).u32Limit             = (a_KvmSeg).limit; \
            (a_CtxSeg).ValidSel = (a_CtxSeg).Sel = (a_KvmSeg).selector; \
            (a_CtxSeg).Attr.n.u4Type        = (a_KvmSeg).type; \
            (a_CtxSeg).Attr.n.u1DescType    = (a_KvmSeg).s; \
            (a_CtxSeg).Attr.n.u2Dpl         = (a_KvmSeg).dpl; \
            (a_CtxSeg).Attr.n.u1Present     = (a_KvmSeg).present; \
            (a_CtxSeg).Attr.n.u1Available   = (a_KvmSeg).avl; \
            (a_CtxSeg).Attr.n.u1Long        = (a_KvmSeg).l; \
            (a_CtxSeg).Attr.n.u1DefBig      = (a_KvmSeg).db; \
            (a_CtxSeg).Attr.n.u1Granularity = (a_KvmSeg).g; \
            (a_CtxSeg).Attr.n.u1Unusable    = (a_KvmSeg).unusable; \
            (a_CtxSeg).fFlags               = CPUMSELREG_FLAGS_VALID; \
            CPUMSELREG_ARE_HIDDEN_PARTS_VALID(pVCpu, &(a_CtxSeg)); \
        } while (0)

        if (fWhat & CPUMCTX_EXTRN_SREG_MASK)
        {
            if (fWhat & CPUMCTX_EXTRN_ES)
                NEM_LNX_IMPORT_SEG(pCtx->es, pRun->s.regs.sregs.es);
            if (fWhat & CPUMCTX_EXTRN_CS)
                NEM_LNX_IMPORT_SEG(pCtx->cs, pRun->s.regs.sregs.cs);
            if (fWhat & CPUMCTX_EXTRN_SS)
                NEM_LNX_IMPORT_SEG(pCtx->ss, pRun->s.regs.sregs.ss);
            if (fWhat & CPUMCTX_EXTRN_DS)
                NEM_LNX_IMPORT_SEG(pCtx->ds, pRun->s.regs.sregs.ds);
            if (fWhat & CPUMCTX_EXTRN_FS)
                NEM_LNX_IMPORT_SEG(pCtx->fs, pRun->s.regs.sregs.fs);
            if (fWhat & CPUMCTX_EXTRN_GS)
                NEM_LNX_IMPORT_SEG(pCtx->gs, pRun->s.regs.sregs.gs);
        }
        if (fWhat & CPUMCTX_EXTRN_TABLE_MASK)
        {
            if (fWhat & CPUMCTX_EXTRN_GDTR)
            {
                pCtx->gdtr.pGdt     = pRun->s.regs.sregs.gdt.base;
                pCtx->gdtr.cbGdt    = pRun->s.regs.sregs.gdt.limit;
            }
            if (fWhat & CPUMCTX_EXTRN_IDTR)
            {
                pCtx->idtr.pIdt     = pRun->s.regs.sregs.idt.base;
                pCtx->idtr.cbIdt    = pRun->s.regs.sregs.idt.limit;
            }
            if (fWhat & CPUMCTX_EXTRN_LDTR)
                NEM_LNX_IMPORT_SEG(pCtx->ldtr, pRun->s.regs.sregs.ldt);
            if (fWhat & CPUMCTX_EXTRN_TR)
                NEM_LNX_IMPORT_SEG(pCtx->tr, pRun->s.regs.sregs.tr);
        }
        if (fWhat & CPUMCTX_EXTRN_CR_MASK)
        {
            if (fWhat & CPUMCTX_EXTRN_CR0)
            {
                if (pVCpu->cpum.GstCtx.cr0 != pRun->s.regs.sregs.cr0)
                {
                    CPUMSetGuestCR0(pVCpu, pRun->s.regs.sregs.cr0);
                    fMaybeChangedMode = true;
                }
            }
            if (fWhat & CPUMCTX_EXTRN_CR2)
                pCtx->cr2              = pRun->s.regs.sregs.cr2;
            if (fWhat & CPUMCTX_EXTRN_CR3)
            {
                if (pCtx->cr3 != pRun->s.regs.sregs.cr3)
                {
                    CPUMSetGuestCR3(pVCpu, pRun->s.regs.sregs.cr3);
                    fUpdateCr3 = true;
                }
            }
            if (fWhat & CPUMCTX_EXTRN_CR4)
            {
                if (pCtx->cr4 != pRun->s.regs.sregs.cr4)
                {
                    CPUMSetGuestCR4(pVCpu, pRun->s.regs.sregs.cr4);
                    fMaybeChangedMode = true;
                }
            }
        }

        if (fWhat & CPUMCTX_EXTRN_EFER)
        {
            if (pCtx->msrEFER != pRun->s.regs.sregs.efer)
            {
                Log7(("NEM/%u: MSR EFER changed %RX64 -> %RX64\n", pVCpu->idCpu,  pVCpu->cpum.GstCtx.msrEFER, pRun->s.regs.sregs.efer));
                if ((pRun->s.regs.sregs.efer ^ pVCpu->cpum.GstCtx.msrEFER) & MSR_K6_EFER_NXE)
                    PGMNotifyNxeChanged(pVCpu, RT_BOOL(pRun->s.regs.sregs.efer & MSR_K6_EFER_NXE));
                pCtx->msrEFER = pRun->s.regs.sregs.efer;
                fMaybeChangedMode = true;
            }
        }
#undef NEM_LNX_IMPORT_SEG
    }

    /*
     * Debug registers.
     */
    if (fWhat & CPUMCTX_EXTRN_DR_MASK)
    {
        struct kvm_debugregs DbgRegs = {{0}};
        int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_DEBUGREGS, &DbgRegs);
        AssertMsgReturn(rc == 0, ("rc=%d errno=%d\n", rc, errno), VERR_NEM_IPE_3);

        if (fWhat & CPUMCTX_EXTRN_DR0_DR3)
        {
            pCtx->dr[0] = DbgRegs.db[0];
            pCtx->dr[1] = DbgRegs.db[1];
            pCtx->dr[2] = DbgRegs.db[2];
            pCtx->dr[3] = DbgRegs.db[3];
        }
        if (fWhat & CPUMCTX_EXTRN_DR6)
            pCtx->dr[6] = DbgRegs.dr6;
        if (fWhat & CPUMCTX_EXTRN_DR7)
            pCtx->dr[7] = DbgRegs.dr7;
    }

    /*
     * FPU, SSE, AVX, ++.
     */
    if (fWhat & (CPUMCTX_EXTRN_X87 | CPUMCTX_EXTRN_SSE_AVX | CPUMCTX_EXTRN_OTHER_XSAVE | CPUMCTX_EXTRN_XCRx))
    {
        if (fWhat & (CPUMCTX_EXTRN_X87 | CPUMCTX_EXTRN_SSE_AVX | CPUMCTX_EXTRN_OTHER_XSAVE))
        {
            fWhat |= CPUMCTX_EXTRN_X87 | CPUMCTX_EXTRN_SSE_AVX | CPUMCTX_EXTRN_OTHER_XSAVE; /* we do all or nothing at all */

            AssertCompile(sizeof(pCtx->XState) >= sizeof(struct kvm_xsave));
            int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_XSAVE, &pCtx->XState);
            AssertMsgReturn(rc == 0, ("rc=%d errno=%d\n", rc, errno), VERR_NEM_IPE_3);
        }

        if (fWhat & CPUMCTX_EXTRN_XCRx)
        {
            struct kvm_xcrs Xcrs =
            {   /*.nr_xcrs = */ 2,
                /*.flags = */   0,
                /*.xcrs= */ {
                    { /*.xcr =*/ 0, /*.reserved=*/ 0, /*.value=*/ pCtx->aXcr[0] },
                    { /*.xcr =*/ 1, /*.reserved=*/ 0, /*.value=*/ pCtx->aXcr[1] },
                }
            };

            int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_XCRS, &Xcrs);
            AssertMsgReturn(rc == 0, ("rc=%d errno=%d\n", rc, errno), VERR_NEM_IPE_3);

            pCtx->aXcr[0] = Xcrs.xcrs[0].value;
            pCtx->aXcr[1] = Xcrs.xcrs[1].value;
            pCtx->fXStateMask = Xcrs.xcrs[0].value;
        }
    }

    /*
     * MSRs.
     */
    if (fWhat & (  CPUMCTX_EXTRN_KERNEL_GS_BASE | CPUMCTX_EXTRN_SYSCALL_MSRS | CPUMCTX_EXTRN_SYSENTER_MSRS
                 | CPUMCTX_EXTRN_TSC_AUX        | CPUMCTX_EXTRN_OTHER_MSRS))
    {
        union
        {
            struct kvm_msrs Core;
            uint64_t padding[2 + sizeof(struct kvm_msr_entry) * 32];
        }                   uBuf;
        uint64_t           *pauDsts[32];
        uint32_t            iMsr        = 0;
        PCPUMCTXMSRS const  pCtxMsrs    = CPUMQueryGuestCtxMsrsPtr(pVCpu);

#define ADD_MSR(a_Msr, a_uValue) do { \
            Assert(iMsr < 32); \
            uBuf.Core.entries[iMsr].index    = (a_Msr); \
            uBuf.Core.entries[iMsr].reserved = 0; \
            uBuf.Core.entries[iMsr].data     = UINT64_MAX; \
            pauDsts[iMsr] = &(a_uValue); \
            iMsr += 1; \
        } while (0)

        if (fWhat & CPUMCTX_EXTRN_KERNEL_GS_BASE)
            ADD_MSR(MSR_K8_KERNEL_GS_BASE, pCtx->msrKERNELGSBASE);
        if (fWhat & CPUMCTX_EXTRN_SYSCALL_MSRS)
        {
            ADD_MSR(MSR_K6_STAR,    pCtx->msrSTAR);
            ADD_MSR(MSR_K8_LSTAR,   pCtx->msrLSTAR);
            ADD_MSR(MSR_K8_CSTAR,   pCtx->msrCSTAR);
            ADD_MSR(MSR_K8_SF_MASK, pCtx->msrSFMASK);
        }
        if (fWhat & CPUMCTX_EXTRN_SYSENTER_MSRS)
        {
            ADD_MSR(MSR_IA32_SYSENTER_CS,  pCtx->SysEnter.cs);
            ADD_MSR(MSR_IA32_SYSENTER_EIP, pCtx->SysEnter.eip);
            ADD_MSR(MSR_IA32_SYSENTER_ESP, pCtx->SysEnter.esp);
        }
        if (fWhat & CPUMCTX_EXTRN_TSC_AUX)
            ADD_MSR(MSR_K8_TSC_AUX, pCtxMsrs->msr.TscAux);
        if (fWhat & CPUMCTX_EXTRN_OTHER_MSRS)
        {
            ADD_MSR(MSR_IA32_CR_PAT, pCtx->msrPAT);
            ADD_MSR(MSR_IA32_ARCH_CAPABILITIES, pCtxMsrs->msr.ArchCaps);
            ADD_MSR(MSR_IA32_SPEC_CTRL, pCtxMsrs->msr.SpecCtrl);
            /** @todo What do we _have_ to add here?
             * We also have: Mttr*, MiscEnable, FeatureControl. */
        }

        uBuf.Core.pad   = 0;
        uBuf.Core.nmsrs = iMsr;
        int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_MSRS, &uBuf);
        AssertMsgReturn(rc == (int)iMsr,
                        ("rc=%d iMsr=%d (->%#x) errno=%d\n",
                         rc, iMsr, (uint32_t)rc < iMsr ? uBuf.Core.entries[rc].index : 0, errno),
                        VERR_NEM_IPE_3);

        while (iMsr-- > 0)
            *pauDsts[iMsr] = uBuf.Core.entries[iMsr].data;
#undef ADD_MSR
    }

    /*
     * Interruptibility state and pending interrupts.
     */
    if (fWhat & (CPUMCTX_EXTRN_INHIBIT_INT | CPUMCTX_EXTRN_INHIBIT_NMI))
    {
        fWhat |= CPUMCTX_EXTRN_INHIBIT_INT | CPUMCTX_EXTRN_INHIBIT_NMI; /* always do both, see export and interrupt FF handling */

        struct kvm_vcpu_events KvmEvents = {0};
        int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_VCPU_EVENTS, &KvmEvents);
        AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_3);

        if (pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_RIP)
            pVCpu->cpum.GstCtx.rip = pRun->s.regs.regs.rip;

        CPUMUpdateInterruptShadowSsStiEx(&pVCpu->cpum.GstCtx,
                                         RT_BOOL(KvmEvents.interrupt.shadow & KVM_X86_SHADOW_INT_MOV_SS),
                                         RT_BOOL(KvmEvents.interrupt.shadow & KVM_X86_SHADOW_INT_STI),
                                         pVCpu->cpum.GstCtx.rip);
        CPUMUpdateInterruptInhibitingByNmi(&pVCpu->cpum.GstCtx, KvmEvents.nmi.masked != 0);

        Assert(KvmEvents.nmi.injected == 0);
        Assert(KvmEvents.nmi.pending  == 0);
    }

    /*
     * Update the external mask.
     */
    pCtx->fExtrn &= ~fWhat;
    pVCpu->cpum.GstCtx.fExtrn &= ~fWhat;
    if (!(pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_ALL))
        pVCpu->cpum.GstCtx.fExtrn = 0;

    /*
     * We sometimes need to update PGM on the guest status.
     */
    if (!fMaybeChangedMode && !fUpdateCr3)
    { /* likely */ }
    else
    {
        /*
         * Make sure we got all the state PGM might need.
         */
        Log7(("nemHCLnxImportState: fMaybeChangedMode=%d fUpdateCr3=%d fExtrnNeeded=%#RX64\n", fMaybeChangedMode, fUpdateCr3,
              pVCpu->cpum.GstCtx.fExtrn & (CPUMCTX_EXTRN_CR0 | CPUMCTX_EXTRN_CR4 | CPUMCTX_EXTRN_CR3 | CPUMCTX_EXTRN_EFER) ));
        if (pVCpu->cpum.GstCtx.fExtrn & (CPUMCTX_EXTRN_CR0 | CPUMCTX_EXTRN_CR4 | CPUMCTX_EXTRN_CR3 | CPUMCTX_EXTRN_EFER))
        {
            if (pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_CR0)
            {
                if (pVCpu->cpum.GstCtx.cr0 != pRun->s.regs.sregs.cr0)
                {
                    CPUMSetGuestCR0(pVCpu, pRun->s.regs.sregs.cr0);
                    fMaybeChangedMode = true;
                }
            }
            if (pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_CR3)
            {
                if (pCtx->cr3 != pRun->s.regs.sregs.cr3)
                {
                    CPUMSetGuestCR3(pVCpu, pRun->s.regs.sregs.cr3);
                    fUpdateCr3 = true;
                }
            }
            if (pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_CR4)
            {
                if (pCtx->cr4 != pRun->s.regs.sregs.cr4)
                {
                    CPUMSetGuestCR4(pVCpu, pRun->s.regs.sregs.cr4);
                    fMaybeChangedMode = true;
                }
            }
            if (fWhat & CPUMCTX_EXTRN_EFER)
            {
                if (pCtx->msrEFER != pRun->s.regs.sregs.efer)
                {
                    Log7(("NEM/%u: MSR EFER changed %RX64 -> %RX64\n", pVCpu->idCpu,  pVCpu->cpum.GstCtx.msrEFER, pRun->s.regs.sregs.efer));
                    if ((pRun->s.regs.sregs.efer ^ pVCpu->cpum.GstCtx.msrEFER) & MSR_K6_EFER_NXE)
                        PGMNotifyNxeChanged(pVCpu, RT_BOOL(pRun->s.regs.sregs.efer & MSR_K6_EFER_NXE));
                    pCtx->msrEFER = pRun->s.regs.sregs.efer;
                    fMaybeChangedMode = true;
                }
            }

            pVCpu->cpum.GstCtx.fExtrn &= ~(CPUMCTX_EXTRN_CR0 | CPUMCTX_EXTRN_CR4 | CPUMCTX_EXTRN_CR3 | CPUMCTX_EXTRN_EFER);
            if (!(pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_ALL))
                pVCpu->cpum.GstCtx.fExtrn = 0;
        }

        /*
         * Notify PGM about the changes.
         */
        if (fMaybeChangedMode)
        {
            int rc = PGMChangeMode(pVCpu, pVCpu->cpum.GstCtx.cr0, pVCpu->cpum.GstCtx.cr4,
                                   pVCpu->cpum.GstCtx.msrEFER, false /*fForce*/);
            AssertMsgReturn(rc == VINF_SUCCESS, ("rc=%Rrc\n", rc), RT_FAILURE_NP(rc) ? rc : VERR_NEM_IPE_1);
        }

        if (fUpdateCr3)
        {
            int rc = PGMUpdateCR3(pVCpu, pVCpu->cpum.GstCtx.cr3);
            if (rc == VINF_SUCCESS)
            { /* likely */ }
            else
                AssertMsgFailedReturn(("rc=%Rrc\n", rc), RT_FAILURE_NP(rc) ? rc : VERR_NEM_IPE_2);
        }
    }

    return VINF_SUCCESS;
}


/**
 * Interface for importing state on demand (used by IEM).
 *
 * @returns VBox status code.
 * @param   pVCpu       The cross context CPU structure.
 * @param   fWhat       What to import, CPUMCTX_EXTRN_XXX.
 */
VMM_INT_DECL(int) NEMImportStateOnDemand(PVMCPUCC pVCpu, uint64_t fWhat)
{
    STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatImportOnDemand);
    return nemHCLnxImportState(pVCpu, fWhat, &pVCpu->cpum.GstCtx, pVCpu->nem.s.pRun);
}


/**
 * Exports state to KVM.
 */
static int nemHCLnxExportState(PVM pVM, PVMCPU pVCpu, PCPUMCTX pCtx, struct kvm_run *pRun)
{
#define NEM_UPDATE_IF_CHANGED(dst, src, dirty_flag) \
        if (src != dst) { \
            dst = src; \
            dirty_flag = true; \
        }


    uint64_t const fExtrn = ~pCtx->fExtrn & CPUMCTX_EXTRN_ALL;
    Assert((~fExtrn & CPUMCTX_EXTRN_ALL) != CPUMCTX_EXTRN_ALL);

    /*
     * Stuff that goes into kvm_run::s.regs.regs:
     */
    if (fExtrn & (CPUMCTX_EXTRN_RIP | CPUMCTX_EXTRN_RFLAGS | CPUMCTX_EXTRN_GPRS_MASK))
    {
        bool dirty_gprs {false};

        if (fExtrn & CPUMCTX_EXTRN_RIP) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rip, pCtx->rip, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RFLAGS) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rflags, pCtx->rflags.u, dirty_gprs);
        }

        if (fExtrn & CPUMCTX_EXTRN_RAX) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rax, pCtx->rax, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RCX) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rcx, pCtx->rcx, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RDX) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rdx, pCtx->rdx, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RBX) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rbx, pCtx->rbx, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RSP) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rsp, pCtx->rsp, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RBP) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rbp, pCtx->rbp, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RSI) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rsi, pCtx->rsi, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_RDI) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.rdi, pCtx->rdi, dirty_gprs);
        }
        if (fExtrn & CPUMCTX_EXTRN_R8_R15)
        {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r8, pCtx->r8, dirty_gprs);
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r9, pCtx->r9, dirty_gprs);
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r10, pCtx->r10, dirty_gprs);
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r11, pCtx->r11, dirty_gprs);
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r12, pCtx->r12, dirty_gprs);
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r13, pCtx->r13, dirty_gprs);
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r14, pCtx->r14, dirty_gprs);
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.regs.r15, pCtx->r15, dirty_gprs);
        }
        if (dirty_gprs) {
            pRun->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
        }
    }

    /*
     * Stuff that goes into kvm_run::s.regs.sregs:
     *
     * The APIC base register updating is a little suboptimal... But at least
     * VBox always has the right base register value, so it's one directional.
     */
    uint64_t const uApicBase = APICGetBaseMsrNoCheck(pVCpu);
    if (   (fExtrn & (  CPUMCTX_EXTRN_SREG_MASK | CPUMCTX_EXTRN_TABLE_MASK | CPUMCTX_EXTRN_CR_MASK
                      | CPUMCTX_EXTRN_EFER      | CPUMCTX_EXTRN_APIC_TPR))
        || uApicBase != pVCpu->nem.s.uKvmApicBase)
    {
#define NEM_LNX_EXPORT_SEG(a_KvmSeg, a_CtxSeg, dirty_flag) do { \
            (a_KvmSeg).base     = (a_CtxSeg).u64Base; \
            (a_KvmSeg).limit    = (a_CtxSeg).u32Limit; \
            (a_KvmSeg).selector = (a_CtxSeg).Sel; \
            (a_KvmSeg).type     = (a_CtxSeg).Attr.n.u4Type; \
            (a_KvmSeg).s        = (a_CtxSeg).Attr.n.u1DescType; \
            (a_KvmSeg).dpl      = (a_CtxSeg).Attr.n.u2Dpl; \
            (a_KvmSeg).present  = (a_CtxSeg).Attr.n.u1Present; \
            (a_KvmSeg).avl      = (a_CtxSeg).Attr.n.u1Available; \
            (a_KvmSeg).l        = (a_CtxSeg).Attr.n.u1Long; \
            (a_KvmSeg).db       = (a_CtxSeg).Attr.n.u1DefBig; \
            (a_KvmSeg).g        = (a_CtxSeg).Attr.n.u1Granularity; \
            (a_KvmSeg).unusable = (a_CtxSeg).Attr.n.u1Unusable; \
            (a_KvmSeg).padding  = 0; \
            dirty_flag = true; \
        } while (0)
#define NEM_LNX_SREG_IDENTICAL(a_KvmSeg, a_CtxSeg) ( \
            (a_KvmSeg).base     == (a_CtxSeg).u64Base && \
            (a_KvmSeg).limit    == (a_CtxSeg).u32Limit && \
            (a_KvmSeg).selector == (a_CtxSeg).Sel && \
            (a_KvmSeg).type     == (a_CtxSeg).Attr.n.u4Type && \
            (a_KvmSeg).s        == (a_CtxSeg).Attr.n.u1DescType && \
            (a_KvmSeg).dpl      == (a_CtxSeg).Attr.n.u2Dpl && \
            (a_KvmSeg).present  == (a_CtxSeg).Attr.n.u1Present && \
            (a_KvmSeg).avl      == (a_CtxSeg).Attr.n.u1Available && \
            (a_KvmSeg).l        == (a_CtxSeg).Attr.n.u1Long && \
            (a_KvmSeg).db       == (a_CtxSeg).Attr.n.u1DefBig && \
            (a_KvmSeg).g        == (a_CtxSeg).Attr.n.u1Granularity && \
            (a_KvmSeg).unusable == (a_CtxSeg).Attr.n.u1Unusable \
        )
        bool dirty_sregs = false;

        if ((pVCpu->nem.s.uKvmApicBase ^ uApicBase) & MSR_IA32_APICBASE_EN)
            Log(("NEM/%u: APICBASE_EN changed %#010RX64 -> %#010RX64\n", pVCpu->idCpu, pVCpu->nem.s.uKvmApicBase, uApicBase));

        NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.apic_base, uApicBase, dirty_sregs);
        NEM_UPDATE_IF_CHANGED(pVCpu->nem.s.uKvmApicBase, uApicBase, dirty_sregs);

        if (fExtrn & CPUMCTX_EXTRN_SREG_MASK)
        {
            if (fExtrn & CPUMCTX_EXTRN_ES and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.es, pCtx->es)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.es, pCtx->es, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_CS and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.cs, pCtx->cs)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.cs, pCtx->cs, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_SS and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.ss, pCtx->ss)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.ss, pCtx->ss, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_DS and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.ds, pCtx->ds)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.ds, pCtx->ds, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_FS and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.fs, pCtx->fs)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.fs, pCtx->fs, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_GS and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.gs, pCtx->gs)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.gs, pCtx->gs, dirty_sregs);
            }

        }
        if (fExtrn & CPUMCTX_EXTRN_TABLE_MASK)
        {
            if (fExtrn & CPUMCTX_EXTRN_GDTR)
            {
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.gdt.base, pCtx->gdtr.pGdt, dirty_sregs);
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.gdt.limit, pCtx->gdtr.cbGdt, dirty_sregs);
                pRun->s.regs.sregs.gdt.padding[0] = 0;
                pRun->s.regs.sregs.gdt.padding[1] = 0;
                pRun->s.regs.sregs.gdt.padding[2] = 0;
            }
            if (fExtrn & CPUMCTX_EXTRN_IDTR)
            {
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.idt.base, pCtx->idtr.pIdt, dirty_sregs);
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.idt.limit, pCtx->idtr.cbIdt, dirty_sregs);
                pRun->s.regs.sregs.idt.padding[0] = 0;
                pRun->s.regs.sregs.idt.padding[1] = 0;
                pRun->s.regs.sregs.idt.padding[2] = 0;
            }
            if (fExtrn & CPUMCTX_EXTRN_LDTR and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.ldt, pCtx->ldtr)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.ldt, pCtx->ldtr, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_TR and not NEM_LNX_SREG_IDENTICAL(pRun->s.regs.sregs.tr, pCtx->tr)) {
                NEM_LNX_EXPORT_SEG(pRun->s.regs.sregs.tr, pCtx->tr, dirty_sregs);
            }

        }
        if (fExtrn & CPUMCTX_EXTRN_CR_MASK)
        {
            if (fExtrn & CPUMCTX_EXTRN_CR0) {
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.cr0, pCtx->cr0, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_CR2) {
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.cr2, pCtx->cr2, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_CR3) {
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.cr3, pCtx->cr3, dirty_sregs);
            }
            if (fExtrn & CPUMCTX_EXTRN_CR4) {
                NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.cr4, pCtx->cr4, dirty_sregs);
            }
        }
        if (fExtrn & CPUMCTX_EXTRN_EFER) {
            NEM_UPDATE_IF_CHANGED(pRun->s.regs.sregs.efer, pCtx->msrEFER, dirty_sregs);
        }


        if (dirty_sregs) {
            pRun->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
        } else {
            // This is a very weird and poorly documented part of the kvm_run structure.
            // https://www.kernel.org/doc/html/latest/virt/kvm/api.html explains this the following way:
            //
            //   interrupt_bitmap is a bitmap of pending external interrupts. At most one bit may be set.
            //   This interrupt has been acknowledged by the APIC but not yet injected into the cpu core.
            //
            // Looking at the kernel part of SET/GET_SREGS, we can see that this is kinda true, but not quite.
            // The kernel sets only 1 bit, but never clears any of the fields. Thus, in order to have only
            // a single bit set, userspace must clear the bitmap iff we haven't modified any SREGS. If we have
            // modified SREGS, we have to transfer the unmodified bitmap back to KVM, because otherwise, we
            // would tell KVM that the injection is no longer pending.
            //
            //
            // This is a nasty interface and we should probably do what Qemu does, that is, using SET/GET_SREGS2
            // where this field is no longer present.
            RT_ZERO(pRun->s.regs.sregs.interrupt_bitmap);
        }

    }
#undef NEM_LNX_EXPORT_SEG
#undef NEM_LNX_SREG_IDENTICAL
#undef NEM_UPDATE_IF_CHANGED

    /*
     * Debug registers.
     */
    if (fExtrn & CPUMCTX_EXTRN_DR_MASK)
    {
        struct kvm_debugregs DbgRegs = {{0}};

        if ((fExtrn & CPUMCTX_EXTRN_DR_MASK) != CPUMCTX_EXTRN_DR_MASK)
        {
            /* Partial debug state, we must get DbgRegs first so we can merge: */
            int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_DEBUGREGS, &DbgRegs);
            AssertMsgReturn(rc == 0, ("rc=%d errno=%d\n", rc, errno), VERR_NEM_IPE_3);
        }

        if (fExtrn & CPUMCTX_EXTRN_DR0_DR3)
        {
            DbgRegs.db[0] = pCtx->dr[0];
            DbgRegs.db[1] = pCtx->dr[1];
            DbgRegs.db[2] = pCtx->dr[2];
            DbgRegs.db[3] = pCtx->dr[3];
        }
        if (fExtrn & CPUMCTX_EXTRN_DR6)
            DbgRegs.dr6 = pCtx->dr[6];
        if (fExtrn & CPUMCTX_EXTRN_DR7)
            DbgRegs.dr7 = pCtx->dr[7];

        int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_DEBUGREGS, &DbgRegs);
        AssertMsgReturn(rc == 0, ("rc=%d errno=%d\n", rc, errno), VERR_NEM_IPE_3);
    }

    /*
     * FPU, SSE, AVX, ++.
     */
    if (fExtrn & (CPUMCTX_EXTRN_X87 | CPUMCTX_EXTRN_SSE_AVX | CPUMCTX_EXTRN_OTHER_XSAVE | CPUMCTX_EXTRN_XCRx))
    {
        if (fExtrn & (CPUMCTX_EXTRN_X87 | CPUMCTX_EXTRN_SSE_AVX | CPUMCTX_EXTRN_OTHER_XSAVE))
        {
            /** @todo could IEM just grab state partial control in some situations? */
            Assert(   (fExtrn & (CPUMCTX_EXTRN_X87 | CPUMCTX_EXTRN_SSE_AVX | CPUMCTX_EXTRN_OTHER_XSAVE))
                   ==           (CPUMCTX_EXTRN_X87 | CPUMCTX_EXTRN_SSE_AVX | CPUMCTX_EXTRN_OTHER_XSAVE)); /* no partial states */

            AssertCompile(sizeof(pCtx->XState) >= sizeof(struct kvm_xsave));
            int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_XSAVE, &pCtx->XState);
            AssertMsgReturn(rc == 0, ("rc=%d errno=%d\n", rc, errno), VERR_NEM_IPE_3);
        }

        if (fExtrn & CPUMCTX_EXTRN_XCRx)
        {
            struct kvm_xcrs Xcrs =
            {   /*.nr_xcrs = */ 2,
                /*.flags = */   0,
                /*.xcrs= */ {
                    { /*.xcr =*/ 0, /*.reserved=*/ 0, /*.value=*/ pCtx->aXcr[0] },
                    { /*.xcr =*/ 1, /*.reserved=*/ 0, /*.value=*/ pCtx->aXcr[1] },
                }
            };

            int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_XCRS, &Xcrs);
            AssertMsgReturn(rc == 0, ("rc=%d errno=%d\n", rc, errno), VERR_NEM_IPE_3);
        }
    }

    /*
     * MSRs.
     */
    if (fExtrn & (  CPUMCTX_EXTRN_KERNEL_GS_BASE | CPUMCTX_EXTRN_SYSCALL_MSRS | CPUMCTX_EXTRN_SYSENTER_MSRS
                  | CPUMCTX_EXTRN_TSC_AUX        | CPUMCTX_EXTRN_OTHER_MSRS))
    {
        union
        {
            struct kvm_msrs Core;
            uint64_t padding[2 + sizeof(struct kvm_msr_entry) * 32];
        }                   uBuf;
        uint32_t            iMsr     = 0;
        PCPUMCTXMSRS const  pCtxMsrs = CPUMQueryGuestCtxMsrsPtr(pVCpu);

#define ADD_MSR(a_Msr, a_uValue) do { \
            Assert(iMsr < 32); \
            uBuf.Core.entries[iMsr].index    = (a_Msr); \
            uBuf.Core.entries[iMsr].reserved = 0; \
            uBuf.Core.entries[iMsr].data     = (a_uValue); \
            iMsr += 1; \
        } while (0)

        if (fExtrn & CPUMCTX_EXTRN_KERNEL_GS_BASE)
            ADD_MSR(MSR_K8_KERNEL_GS_BASE, pCtx->msrKERNELGSBASE);
        if (fExtrn & CPUMCTX_EXTRN_SYSCALL_MSRS)
        {
            ADD_MSR(MSR_K6_STAR,    pCtx->msrSTAR);
            ADD_MSR(MSR_K8_LSTAR,   pCtx->msrLSTAR);
            ADD_MSR(MSR_K8_CSTAR,   pCtx->msrCSTAR);
            ADD_MSR(MSR_K8_SF_MASK, pCtx->msrSFMASK);
        }
        if (fExtrn & CPUMCTX_EXTRN_SYSENTER_MSRS)
        {
            ADD_MSR(MSR_IA32_SYSENTER_CS,  pCtx->SysEnter.cs);
            ADD_MSR(MSR_IA32_SYSENTER_EIP, pCtx->SysEnter.eip);
            ADD_MSR(MSR_IA32_SYSENTER_ESP, pCtx->SysEnter.esp);
        }
        if (fExtrn & CPUMCTX_EXTRN_TSC_AUX)
            ADD_MSR(MSR_K8_TSC_AUX, pCtxMsrs->msr.TscAux);
        if (fExtrn & CPUMCTX_EXTRN_OTHER_MSRS)
        {
            ADD_MSR(MSR_IA32_CR_PAT, pCtx->msrPAT);
            ADD_MSR(MSR_IA32_ARCH_CAPABILITIES, pCtxMsrs->msr.ArchCaps);
            ADD_MSR(MSR_IA32_SPEC_CTRL, pCtxMsrs->msr.SpecCtrl);
            /** @todo What do we _have_ to add here?
             * We also have: Mttr*, MiscEnable, FeatureControl. */
        }

        uBuf.Core.pad   = 0;
        uBuf.Core.nmsrs = iMsr;
        int rc = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_MSRS, &uBuf);
        AssertMsgReturn(rc == (int)iMsr,
                        ("rc=%d iMsr=%d (->%#x) errno=%d\n",
                         rc, iMsr, (uint32_t)rc < iMsr ? uBuf.Core.entries[rc].index : 0, errno),
                        VERR_NEM_IPE_3);
    }

    /*
     * Interruptibility state.
     *
     * Note! This I/O control function sets most fields passed in, so when
     *       raising an interrupt, NMI, SMI or exception, this must be done
     *       by the code doing the rasing or we'll overwrite it here.
     */
    if (fExtrn & (CPUMCTX_EXTRN_INHIBIT_INT | CPUMCTX_EXTRN_INHIBIT_NMI))
    {
        Assert(   (fExtrn & (CPUMCTX_EXTRN_INHIBIT_INT | CPUMCTX_EXTRN_INHIBIT_NMI))
               ==           (CPUMCTX_EXTRN_INHIBIT_INT | CPUMCTX_EXTRN_INHIBIT_NMI));

        struct kvm_vcpu_events KvmEvents = {0};
        int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_VCPU_EVENTS, &KvmEvents);
        AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_5);

        KvmEvents.flags = KVM_VCPUEVENT_VALID_SHADOW;
        if (!CPUMIsInInterruptShadowWithUpdate(&pVCpu->cpum.GstCtx))
        { /* probably likely */ }
        else
            KvmEvents.interrupt.shadow = (CPUMIsInInterruptShadowAfterSs(&pVCpu->cpum.GstCtx)  ? KVM_X86_SHADOW_INT_MOV_SS : 0)
                                       | (CPUMIsInInterruptShadowAfterSti(&pVCpu->cpum.GstCtx) ? KVM_X86_SHADOW_INT_STI    : 0);

        /* No flag - this is updated unconditionally. */
        KvmEvents.nmi.masked = CPUMAreInterruptsInhibitedByNmi(&pVCpu->cpum.GstCtx);

        rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_VCPU_EVENTS, &KvmEvents);
        AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_3);
    }

    /*
     * KVM now owns all the state.
     */
    pCtx->fExtrn = CPUMCTX_EXTRN_KEEPER_NEM | CPUMCTX_EXTRN_ALL;

    RT_NOREF(pVM);
    return VINF_SUCCESS;
}


/**
 * Query the CPU tick counter and optionally the TSC_AUX MSR value.
 *
 * @returns VBox status code.
 * @param   pVCpu       The cross context CPU structure.
 * @param   pcTicks     Where to return the CPU tick count.
 * @param   puAux       Where to return the TSC_AUX register value.
 */
VMM_INT_DECL(int) NEMHCQueryCpuTick(PVMCPUCC pVCpu, uint64_t *pcTicks, uint32_t *puAux)
{
    STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatQueryCpuTick);

    // This function is called when the VM is paused or
    // suspended. It's called for all vCPUs.

    const size_t NMSRS = 2;

    size_t szReq = RT_UOFFSETOF_DYN(struct kvm_msrs, entries[NMSRS]);
    struct kvm_msrs *pReq = static_cast<kvm_msrs *>(alloca(szReq));
    memset(pReq, 0, szReq);

    pReq->nmsrs = NMSRS;
    pReq->entries[0].index = MSR_IA32_TSC;
    pReq->entries[1].index = MSR_K8_TSC_AUX;

    int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_MSRS, pReq);
    AssertLogRelMsgReturn(rcLnx == NMSRS, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_5);

    if (pcTicks) {
      *pcTicks = pReq->entries[0].data;
    }

    if (puAux) {
      *puAux = static_cast<uint32_t>(pReq->entries[1].data);
    }

    return VINF_SUCCESS;
}


/**
 * Resumes CPU clock (TSC) on all virtual CPUs.
 *
 * This is called by TM when the VM is started, restored, resumed or similar.
 *
 * @returns VBox status code.
 * @param   pVM             The cross context VM structure.
 * @param   pVCpu           The cross context CPU structure of the calling EMT.
 * @param   uPausedTscValue The TSC value at the time of pausing.
 */
VMM_INT_DECL(int) NEMHCResumeCpuTickOnAll(PVMCC pVM, PVMCPUCC pVCpu, uint64_t uPausedTscValue)
{
    RT_NOREF(pVCpu);

    // This function is called once during unpause or resume. Despite
    // the pVCpu parameter it is _not_ called for all vCPUs.

    const size_t NMSRS = 1;

    size_t szReq = RT_UOFFSETOF_DYN(struct kvm_msrs, entries[NMSRS]);
    struct kvm_msrs *pReq = static_cast<kvm_msrs *>(alloca(szReq));
    memset(pReq, 0, szReq);

    pReq->nmsrs = NMSRS;
    pReq->entries[0].index = MSR_IA32_TSC;
    pReq->entries[0].data = uPausedTscValue;

    // Setting the individual TSC values of all CPUs is fundamentally
    // flawed, because the TSCs keep ticking while we set them. That
    // means that we never really end up with synchronized TSC values
    // unless KVM's built-in TSC synchronization magic fixes things up
    // for us. But the interface doesn't leave us a lot of choice here
    // for now.
    //
    // A better approach would be to use KVM_GET_CLOCK/KVM_SET_CLOCK
    // and restore TSC_ADJUST values. We should validate whether this
    // does the right thing though first.
    for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
    {
        PVMCPU pVCpuCur = pVM->apCpusR3[idCpu];

        int rcLnx = ioctl(pVCpuCur->nem.s.fdVCpu, KVM_SET_MSRS, pReq);
        AssertLogRelMsgReturn(rcLnx == NMSRS, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_5);
    }

    return VINF_SUCCESS;
}


VMM_INT_DECL(uint32_t) NEMHCGetFeatures(PVMCC pVM)
{
    RT_NOREF(pVM);
    return NEM_FEAT_F_NESTED_PAGING
         | NEM_FEAT_F_FULL_GST_EXEC
         | NEM_FEAT_F_XSAVE_XRSTOR;
}



/*********************************************************************************************************************************
*   Execution                                                                                                                    *
*********************************************************************************************************************************/


VMMR3_INT_DECL(bool) NEMR3CanExecuteGuest(PVM pVM, PVMCPU pVCpu)
{
#ifndef VBOX_WITH_KVM_IRQCHIP_FULL
    /*
     * Only execute when the A20 gate is enabled as I cannot immediately
     * spot any A20 support in KVM.
     */
    RT_NOREF(pVM);
    Assert(VM_IS_NEM_ENABLED(pVM));
    return PGMPhysIsA20Enabled(pVCpu);
#else
    /*
     * In full-irqchip mode, we always need to execute via KVM because we
     * have no other way to inject interrupt into the guest (because the PIC is
     * in the kernel!). Otherwise, we will break non-UEFI boot. This will
     * break DOS support.
     */
    return true;
#endif
}


bool nemR3NativeSetSingleInstruction(PVM pVM, PVMCPU pVCpu, bool fEnable)
{
    NOREF(pVM); NOREF(pVCpu); NOREF(fEnable);
    return false;
}


void nemR3NativeNotifyFF(PVM pVM, PVMCPU pVCpu, uint32_t fFlags)
{
    if (pVCpu->hThread == RTThreadSelf()) {
        // RTThreadPoke doesn't like poking the current thread. We can
        // safely return here because the vCPU thread is currently handling
        // an exit and will will check all conditions again when we re-enter
        // the run-loop.
        return;
    }

    int rc = RTThreadPoke(pVCpu->hThread);
    LogFlow(("nemR3NativeNotifyFF: #%u -> %Rrc\n", pVCpu->idCpu, rc));
    AssertRC(rc);
    RT_NOREF(pVM, fFlags);
}


DECLHIDDEN(bool) nemR3NativeNotifyDebugEventChanged(PVM pVM, bool fUseDebugLoop)
{
    RT_NOREF(pVM, fUseDebugLoop);
    return false;
}


DECLHIDDEN(bool) nemR3NativeNotifyDebugEventChangedPerCpu(PVM pVM, PVMCPU pVCpu, bool fUseDebugLoop)
{
    RT_NOREF(pVM, pVCpu, fUseDebugLoop);
    return false;
}


/**
 * Deals with pending interrupt FFs prior to executing guest code.
 */
static VBOXSTRICTRC nemHCLnxHandleInterruptFF(PVM pVM, PVMCPU pVCpu, struct kvm_run *pRun)
{
    RT_NOREF_PV(pVM);

    /*
     * Do not doing anything if TRPM has something pending already as we can
     * only inject one event per KVM_RUN call.  This can only happend if we
     * can directly from the loop in EM, so the inhibit bits must be internal.
     */
    if (TRPMHasTrap(pVCpu))
    {
        Log8(("nemHCLnxHandleInterruptFF: TRPM has an pending event already\n"));

        return VINF_SUCCESS;
    }

    /*
     * First update APIC.  We ASSUME this won't need TPR/CR8.
     */
    if (VMCPU_FF_TEST_AND_CLEAR(pVCpu, VMCPU_FF_UPDATE_APIC))
    {
        AssertLogRelMsgReturn(false, ("VMCPU_FF_UPDATE_APIC is set"), VERR_NEM_IPE_5);
    }

    if (!VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_INTERRUPT_PIC | VMCPU_FF_INTERRUPT_NMI  | VMCPU_FF_INTERRUPT_SMI))
        return VINF_SUCCESS;

    /*
     * We don't currently implement SMIs.
     */
    AssertReturn(!VMCPU_FF_IS_SET(pVCpu, VMCPU_FF_INTERRUPT_SMI), VERR_NEM_IPE_0);

    /*
     * In KVM the CPUMCTX_EXTRN_INHIBIT_INT and CPUMCTX_EXTRN_INHIBIT_NMI states
     * are tied together with interrupt and NMI delivery, so we must get and
     * synchronize these all in one go and set both CPUMCTX_EXTRN_INHIBIT_XXX flags.
     * If we don't we may lose the interrupt/NMI we marked pending here when the
     * state is exported again before execution.
     */
    struct kvm_vcpu_events KvmEvents = {0};
    int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_VCPU_EVENTS, &KvmEvents);
    AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_5);

    if (!(pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_RIP))
        pRun->s.regs.regs.rip = pVCpu->cpum.GstCtx.rip;

    KvmEvents.flags |= KVM_VCPUEVENT_VALID_SHADOW;
    if (!(pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_INHIBIT_INT))
        KvmEvents.interrupt.shadow = !CPUMIsInInterruptShadowWithUpdate(&pVCpu->cpum.GstCtx) ? 0
                                   :   (CPUMIsInInterruptShadowAfterSs(&pVCpu->cpum.GstCtx)  ? KVM_X86_SHADOW_INT_MOV_SS : 0)
                                     | (CPUMIsInInterruptShadowAfterSti(&pVCpu->cpum.GstCtx) ? KVM_X86_SHADOW_INT_STI    : 0);
    else
        CPUMUpdateInterruptShadowSsStiEx(&pVCpu->cpum.GstCtx,
                                         RT_BOOL(KvmEvents.interrupt.shadow & KVM_X86_SHADOW_INT_MOV_SS),
                                         RT_BOOL(KvmEvents.interrupt.shadow & KVM_X86_SHADOW_INT_STI),
                                         pRun->s.regs.regs.rip);

    if (!(pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_INHIBIT_NMI))
        KvmEvents.nmi.masked = CPUMAreInterruptsInhibitedByNmi(&pVCpu->cpum.GstCtx);
    else
        CPUMUpdateInterruptInhibitingByNmi(&pVCpu->cpum.GstCtx, KvmEvents.nmi.masked != 0);

    /* KVM will own the INT + NMI inhibit state soon: */
    pVCpu->cpum.GstCtx.fExtrn = (pVCpu->cpum.GstCtx.fExtrn & ~CPUMCTX_EXTRN_KEEPER_MASK)
                              | CPUMCTX_EXTRN_KEEPER_NEM | CPUMCTX_EXTRN_INHIBIT_INT | CPUMCTX_EXTRN_INHIBIT_NMI;

    /*
     * NMI? Try deliver it first.
     */
    if (VMCPU_FF_IS_SET(pVCpu, VMCPU_FF_INTERRUPT_NMI))
    {
#if 0
        int rcLnx = ioctl(pVCpu->nem.s.fdVm, KVM_NMI, 0UL);
        AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_5);
#else
        KvmEvents.flags      |= KVM_VCPUEVENT_VALID_NMI_PENDING;
        KvmEvents.nmi.pending = 1;
#endif
        VMCPU_FF_CLEAR(pVCpu, VMCPU_FF_INTERRUPT_NMI);
        Log8(("Queuing NMI on %u\n", pVCpu->idCpu));
    }

#ifdef VBOX_WITH_KVM_IRQCHIP_FULL
    AssertLogRelMsg(!VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_INTERRUPT_PIC), ("PDM has pic interrupt but full irqchip is enabled"));
#else
    /*
     * PIC interrupt?
     */
    if (VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_INTERRUPT_PIC))
    {
        if (pRun->s.regs.regs.rflags & X86_EFL_IF)
        {
            if (pRun->ready_for_interrupt_injection)
            {
                uint8_t bInterrupt;
                int rc = PDMGetInterrupt(pVCpu, &bInterrupt);
                if (RT_SUCCESS(rc))
                {
                    TRPMAssertTrap(pVCpu, bInterrupt, TRPM_HARDWARE_INT);

                    Log8(("Queuing interrupt %#x on %u: %04x:%08RX64 efl=%#x\n", bInterrupt, pVCpu->idCpu,
                          pVCpu->cpum.GstCtx.cs.Sel, pVCpu->cpum.GstCtx.rip, pVCpu->cpum.GstCtx.eflags.u));
                }
                else if (rc == VERR_APIC_INTR_MASKED_BY_TPR) /** @todo this isn't extremely efficient if we get a lot of exits... */
                    Log8(("VERR_APIC_INTR_MASKED_BY_TPR\n")); /* We'll get a TRP exit - no interrupt window needed. */
                else
                    Log8(("PDMGetInterrupt failed -> %Rrc\n", rc));
            }
            else
            {
                pRun->request_interrupt_window = 1;
                Log8(("Interrupt window pending on %u (#2)\n", pVCpu->idCpu));
            }
        }
        else
        {
            pRun->request_interrupt_window = 1;
            Log8(("Interrupt window pending on %u (#1)\n", pVCpu->idCpu));
        }
    }
#endif
    /*
     * Now, update the state.
     */
    /** @todo skip when possible...   */
    rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_SET_VCPU_EVENTS, &KvmEvents);
    AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_5);

    return VINF_SUCCESS;
}


/**
 * Handles KVM_EXIT_INTERNAL_ERROR.
 */
static VBOXSTRICTRC nemR3LnxHandleInternalError(PVMCPU pVCpu, struct kvm_run *pRun)
{
    Log(("NEM: KVM_EXIT_INTERNAL_ERROR! suberror=%#x (%d) ndata=%u data=%.*Rhxs\n", pRun->internal.suberror,
         pRun->internal.suberror, pRun->internal.ndata, sizeof(pRun->internal.data), &pRun->internal.data[0]));

    /*
     * Deal with each suberror, returning if we don't want IEM to handle it.
     */
    switch (pRun->internal.suberror)
    {
        case KVM_INTERNAL_ERROR_EMULATION:
        {
            EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_NEM, NEMEXITTYPE_INTERNAL_ERROR_EMULATION),
                             pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitInternalErrorEmulation);
            break;
        }

        case KVM_INTERNAL_ERROR_SIMUL_EX:
        case KVM_INTERNAL_ERROR_DELIVERY_EV:
        case KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON:
        default:
        {
            EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_NEM, NEMEXITTYPE_INTERNAL_ERROR_FATAL),
                             pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitInternalErrorFatal);
            const char *pszName;
            switch (pRun->internal.suberror)
            {
                case KVM_INTERNAL_ERROR_EMULATION:              pszName = "KVM_INTERNAL_ERROR_EMULATION"; break;
                case KVM_INTERNAL_ERROR_SIMUL_EX:               pszName = "KVM_INTERNAL_ERROR_SIMUL_EX"; break;
                case KVM_INTERNAL_ERROR_DELIVERY_EV:            pszName = "KVM_INTERNAL_ERROR_DELIVERY_EV"; break;
                case KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON: pszName = "KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON"; break;
                default:                                        pszName = "unknown"; break;
            }
            LogRel(("NEM: KVM_EXIT_INTERNAL_ERROR! suberror=%#x (%s) ndata=%u data=%.*Rhxs\n", pRun->internal.suberror, pszName,
                    pRun->internal.ndata, sizeof(pRun->internal.data), &pRun->internal.data[0]));
            return VERR_NEM_IPE_0;
        }
    }

    /*
     * Execute instruction in IEM and try get on with it.
     */
    Log2(("nemR3LnxHandleInternalError: Executing instruction at %04x:%08RX64 in IEM\n",
          pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip));
    VBOXSTRICTRC rcStrict = nemHCLnxImportState(pVCpu,
                                                IEM_CPUMCTX_EXTRN_MUST_MASK | CPUMCTX_EXTRN_INHIBIT_INT
                                                 | CPUMCTX_EXTRN_INHIBIT_NMI,
                                                &pVCpu->cpum.GstCtx, pRun);
    if (RT_SUCCESS(rcStrict))
        rcStrict = IEMExecOne(pVCpu);
    return rcStrict;
}


/**
 * Handles KVM_EXIT_IO.
 */
static VBOXSTRICTRC nemHCLnxHandleExitIo(PVMCC pVM, PVMCPUCC pVCpu, struct kvm_run *pRun)
{
    /*
     * Input validation.
     */
    Assert(pRun->io.count > 0);
    Assert(pRun->io.size == 1 || pRun->io.size == 2 || pRun->io.size == 4);
    Assert(pRun->io.direction == KVM_EXIT_IO_IN || pRun->io.direction == KVM_EXIT_IO_OUT);
    Assert(pRun->io.data_offset < pVM->nem.s.cbVCpuMmap);
    Assert(pRun->io.data_offset + pRun->io.size * pRun->io.count <= pVM->nem.s.cbVCpuMmap);

    /*
     * We cannot easily act on the exit history here, because the I/O port
     * exit is stateful and the instruction will be completed in the next
     * KVM_RUN call.  There seems no way to avoid this.
     */
    EMHistoryAddExit(pVCpu,
                     pRun->io.count == 1
                     ? (  pRun->io.direction == KVM_EXIT_IO_IN
                        ? EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_IO_PORT_READ)
                        : EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_IO_PORT_WRITE))
                     : (  pRun->io.direction == KVM_EXIT_IO_IN
                        ? EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_IO_PORT_STR_READ)
                        : EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_IO_PORT_STR_WRITE)),
                     pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());

    /*
     * Do the requested job.
     */
    VBOXSTRICTRC    rcStrict;
    RTPTRUNION      uPtrData;
    uPtrData.pu8 = (uint8_t *)pRun + pRun->io.data_offset;
    if (pRun->io.count == 1)
    {
        if (pRun->io.direction == KVM_EXIT_IO_IN)
        {
            uint32_t uValue = 0;
            rcStrict = IOMIOPortRead(pVM, pVCpu, pRun->io.port, &uValue, pRun->io.size);
            Log4(("IOExit/%u: %04x:%08RX64: IN %#x LB %u -> %#x, rcStrict=%Rrc\n",
                  pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip,
                  pRun->io.port, pRun->io.size, uValue, VBOXSTRICTRC_VAL(rcStrict) ));
            if (IOM_SUCCESS(rcStrict))
            {
                if (pRun->io.size == 4)
                    *uPtrData.pu32 = uValue;
                else if (pRun->io.size == 2)
                    *uPtrData.pu16 = (uint16_t)uValue;
                else
                    *uPtrData.pu8  = (uint8_t)uValue;
            }
        }
        else
        {
            uint32_t const uValue = pRun->io.size == 4 ? *uPtrData.pu32
                                  : pRun->io.size == 2 ? *uPtrData.pu16
                                  :                      *uPtrData.pu8;
            rcStrict = IOMIOPortWrite(pVM, pVCpu, pRun->io.port, uValue, pRun->io.size);
            Log4(("IOExit/%u: %04x:%08RX64: OUT %#x, %#x LB %u rcStrict=%Rrc\n",
                  pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip,
                  pRun->io.port, uValue, pRun->io.size, VBOXSTRICTRC_VAL(rcStrict) ));
        }
    }
    else
    {
        uint32_t cTransfers = pRun->io.count;
        if (pRun->io.direction == KVM_EXIT_IO_IN)
        {
            rcStrict = IOMIOPortReadString(pVM, pVCpu, pRun->io.port, uPtrData.pv, &cTransfers, pRun->io.size);
            Log4(("IOExit/%u: %04x:%08RX64: REP INS %#x LB %u * %#x times -> rcStrict=%Rrc cTransfers=%d\n",
                  pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip,
                  pRun->io.port, pRun->io.size, pRun->io.count, VBOXSTRICTRC_VAL(rcStrict), cTransfers ));
        }
        else
        {
            rcStrict = IOMIOPortWriteString(pVM, pVCpu, pRun->io.port, uPtrData.pv, &cTransfers, pRun->io.size);
            Log4(("IOExit/%u: %04x:%08RX64: REP OUTS %#x LB %u * %#x times -> rcStrict=%Rrc cTransfers=%d\n",
                  pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip,
                  pRun->io.port, pRun->io.size, pRun->io.count, VBOXSTRICTRC_VAL(rcStrict), cTransfers ));
        }
        Assert(cTransfers == 0);
    }
    return rcStrict;
}


/**
 * Handles KVM_EXIT_MMIO.
 */
static VBOXSTRICTRC nemHCLnxHandleExitMmio(PVMCC pVM, PVMCPUCC pVCpu, struct kvm_run *pRun)
{
    /*
     * Input validation.
     */
    Assert(pRun->mmio.len <= sizeof(pRun->mmio.data));
    Assert(pRun->mmio.is_write <= 1);

    /*
     * We cannot easily act on the exit history here, because the MMIO port
     * exit is stateful and the instruction will be completed in the next
     * KVM_RUN call.  There seems no way to circumvent this.
     */
    EMHistoryAddExit(pVCpu,
                     pRun->mmio.is_write
                     ? EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_MMIO_WRITE)
                     : EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_MMIO_READ),
                     pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());

    /*
     * Do the requested job.
     */
    VBOXSTRICTRC rcStrict;
    if (pRun->mmio.is_write)
    {
        /*
         * Sync LAPIC TPR register with cr8 from KVM. This is required as long
         * as we don't use KVM's IRQCHIP feature.
         *
         * This doesn't cover the X2APIC mode. But the whole cr8-code will be
         * gone very soon anyway as we will use KVM's split-irqchip.
         */
        if (pRun->mmio.phys_addr == XAPIC_TPR_ADDR) {
            pRun->cr8 = *pRun->mmio.data >> LAPIC_TPR_SHIFT;
        }
        rcStrict = PGMPhysWrite(pVM, pRun->mmio.phys_addr, pRun->mmio.data, pRun->mmio.len, PGMACCESSORIGIN_HM);
        Log4(("MmioExit/%u: %04x:%08RX64: WRITE %#x LB %u, %.*Rhxs -> rcStrict=%Rrc\n",
              pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip,
              pRun->mmio.phys_addr, pRun->mmio.len, pRun->mmio.len, pRun->mmio.data, VBOXSTRICTRC_VAL(rcStrict) ));
    }
    else
    {
        rcStrict = PGMPhysRead(pVM, pRun->mmio.phys_addr, pRun->mmio.data, pRun->mmio.len, PGMACCESSORIGIN_HM);
        Log4(("MmioExit/%u: %04x:%08RX64: READ %#x LB %u -> %.*Rhxs rcStrict=%Rrc\n",
              pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip,
              pRun->mmio.phys_addr, pRun->mmio.len, pRun->mmio.len, pRun->mmio.data, VBOXSTRICTRC_VAL(rcStrict) ));
    }
    return rcStrict;
}


/**
 * Handles KVM_EXIT_RDMSR
 */
static VBOXSTRICTRC nemHCLnxHandleExitRdMsr(PVMCPUCC pVCpu, struct kvm_run *pRun)
{
    /*
     * Input validation.
     */
    Assert(   pRun->msr.reason == KVM_MSR_EXIT_REASON_INVAL
           || pRun->msr.reason == KVM_MSR_EXIT_REASON_UNKNOWN
           || pRun->msr.reason == KVM_MSR_EXIT_REASON_FILTER);

    /*
     * We cannot easily act on the exit history here, because the MSR exit is
     * stateful and the instruction will be completed in the next KVM_RUN call.
     * There seems no way to circumvent this.
     */
    EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_MSR_READ),
                     pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());

    /*
     * Do the requested job.
     */
    uint64_t uValue = 0;
    VBOXSTRICTRC rcStrict = CPUMQueryGuestMsr(pVCpu, pRun->msr.index, &uValue);
    pRun->msr.data = uValue;
    if (rcStrict != VERR_CPUM_RAISE_GP_0)
    {
        Log3(("MsrRead/%u: %04x:%08RX64: msr=%#010x (reason=%#x) -> %#RX64 rcStrict=%Rrc\n", pVCpu->idCpu,
              pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip, pRun->msr.index, pRun->msr.reason, uValue, VBOXSTRICTRC_VAL(rcStrict) ));
        pRun->msr.error = 0;
    }
    else
    {
        Log3(("MsrRead/%u: %04x:%08RX64: msr=%#010x (reason%#x)-> %#RX64 rcStrict=#GP!\n", pVCpu->idCpu,
              pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip, pRun->msr.index, pRun->msr.reason, uValue));
        pRun->msr.error = 1;
        rcStrict = VINF_SUCCESS;
    }
    return rcStrict;
}


/**
 * Handles KVM_EXIT_WRMSR
 */
static VBOXSTRICTRC nemHCLnxHandleExitWrMsr(PVMCPUCC pVCpu, struct kvm_run *pRun)
{
    /*
     * Input validation.
     */
    Assert(   pRun->msr.reason == KVM_MSR_EXIT_REASON_INVAL
           || pRun->msr.reason == KVM_MSR_EXIT_REASON_UNKNOWN
           || pRun->msr.reason == KVM_MSR_EXIT_REASON_FILTER);

    /*
     * We cannot easily act on the exit history here, because the MSR exit is
     * stateful and the instruction will be completed in the next KVM_RUN call.
     * There seems no way to circumvent this.
     */
    EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_EM, EMEXITTYPE_MSR_WRITE),
                     pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());

    /*
     * Do the requested job.
     */
    VBOXSTRICTRC rcStrict = CPUMSetGuestMsr(pVCpu, pRun->msr.index, pRun->msr.data);
    if (rcStrict != VERR_CPUM_RAISE_GP_0)
    {
        Log3(("MsrWrite/%u: %04x:%08RX64: msr=%#010x := %#RX64 (reason=%#x) -> rcStrict=%Rrc\n", pVCpu->idCpu,
              pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip, pRun->msr.index, pRun->msr.data, pRun->msr.reason, VBOXSTRICTRC_VAL(rcStrict) ));
        pRun->msr.error = 0;
    }
    else
    {
        Log3(("MsrWrite/%u: %04x:%08RX64: msr=%#010x := %#RX64 (reason%#x)-> rcStrict=#GP!\n", pVCpu->idCpu,
              pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip, pRun->msr.index, pRun->msr.data, pRun->msr.reason));
        pRun->msr.error = 1;
        rcStrict = VINF_SUCCESS;
    }
    return rcStrict;
}

static VBOXSTRICTRC nemHCLnxHandleExit(PVMCC pVM, PVMCPUCC pVCpu, struct kvm_run *pRun, bool *pfStatefulExit)
{
    STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitTotal);
    switch (pRun->exit_reason)
    {
        case KVM_EXIT_EXCEPTION:
            AssertFailed();
            break;

        case KVM_EXIT_IO:
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitIo);
            *pfStatefulExit = true;
            return nemHCLnxHandleExitIo(pVM, pVCpu, pRun);

        case KVM_EXIT_MMIO:
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitMmio);
            *pfStatefulExit = true;
            return nemHCLnxHandleExitMmio(pVM, pVCpu, pRun);

        case KVM_EXIT_IRQ_WINDOW_OPEN:
            EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_NEM, NEMEXITTYPE_INTTERRUPT_WINDOW),
                             pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitIrqWindowOpen);
            Log5(("IrqWinOpen/%u: %d\n", pVCpu->idCpu, pRun->request_interrupt_window));
            pRun->request_interrupt_window = 0;
            return VINF_SUCCESS;

        case KVM_EXIT_SET_TPR:
            AssertFailed();
            break;

        case KVM_EXIT_TPR_ACCESS:
            AssertFailed();
            break;

        case KVM_EXIT_X86_RDMSR:
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitRdMsr);
            *pfStatefulExit = true;
            return nemHCLnxHandleExitRdMsr(pVCpu, pRun);

        case KVM_EXIT_X86_WRMSR:
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitWrMsr);
            *pfStatefulExit = true;
            return nemHCLnxHandleExitWrMsr(pVCpu, pRun);

        case KVM_EXIT_HLT:
            EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_NEM, NEMEXITTYPE_HALT),
                             pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitHalt);
            Log5(("Halt/%u\n", pVCpu->idCpu));
            return VINF_EM_HALT;

        case KVM_EXIT_INTR: /* EINTR */
            EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_NEM, NEMEXITTYPE_INTERRUPTED),
                             pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitIntr);
            Log5(("Intr/%u\n", pVCpu->idCpu));

            /* If we don't consume the poke signal, subsequent KVM_RUN invocations will immediately return EINTR again. */
            nemR3LnxConsumePokeSignal();

            return VINF_SUCCESS;

        case KVM_EXIT_HYPERCALL:
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitHypercall);
            AssertFailed();
            break;

        case KVM_EXIT_DEBUG:
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitDebug);
            AssertFailed();
            break;

        case KVM_EXIT_SYSTEM_EVENT:
            AssertFailed();
            break;
        case KVM_EXIT_IOAPIC_EOI:
            PDMIoApicBroadcastEoi(pVM, pRun->eoi.vector);
            return VINF_SUCCESS;
        case KVM_EXIT_HYPERV:
            Assert(pVM->gim.s.enmProviderId == GIMPROVIDERID_HYPERV);

            switch (pRun->hyperv.type)
            {
            case KVM_EXIT_HYPERV_SYNDBG:
                /* The synthetic debugger is not enabled and we should not get these exits. */
                AssertFailed();
                break;
            case KVM_EXIT_HYPERV_HCALL:
                LogRel2(("Hyper-V hcall input:%lx p0:%lx p1:%lx\n", pRun->hyperv.u.hcall.input, pRun->hyperv.u.hcall.params[0], pRun->hyperv.u.hcall.params[1]));

                /* TODO KVM handles the performance-critical hypercalls on its own. We get mostly extended hypercalls
                   here. We would need to forward them to gimHvHypercall. None of these features are enabled right now,
                   so we can just deny the hypercall right away. */

                pRun->hyperv.u.hcall.result = GIM_HV_STATUS_ACCESS_DENIED;
                break;
            case KVM_EXIT_HYPERV_SYNIC:
                LogRel2(("HyperV synic msr:%lx control:%lx evt_page:%lx msg_page:%lx\n",
                         pRun->hyperv.u.synic.msr,
                         pRun->hyperv.u.synic.control,
                         pRun->hyperv.u.synic.evt_page,
                         pRun->hyperv.u.synic.msg_page));

                switch (pRun->hyperv.u.synic.msr)
                {
                case MSR_GIM_HV_SCONTROL:
                case MSR_GIM_HV_SIMP:
                case MSR_GIM_HV_SIEFP:
                    break;
                default:
                    AssertReleaseFailed();
                }
                break;
            default:
                AssertReleaseFailed();
            }

            return VINF_SUCCESS;

        case KVM_EXIT_DIRTY_RING_FULL:
            AssertFailed();
            break;
        case KVM_EXIT_AP_RESET_HOLD:
            AssertFailed();
            break;
        case KVM_EXIT_X86_BUS_LOCK:
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatExitBusLock);
            AssertFailed();
            break;


        case KVM_EXIT_SHUTDOWN:
            AssertFailed();
            break;

        case KVM_EXIT_FAIL_ENTRY:
            LogRel(("NEM: KVM_EXIT_FAIL_ENTRY! hardware_entry_failure_reason=%#x cpu=%#x\n",
                    pRun->fail_entry.hardware_entry_failure_reason, pRun->fail_entry.cpu));
            EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_NEM, NEMEXITTYPE_FAILED_ENTRY),
                             pRun->s.regs.regs.rip + pRun->s.regs.sregs.cs.base, ASMReadTSC());
            return VERR_NEM_IPE_1;

        case KVM_EXIT_INTERNAL_ERROR:
            /* we're counting sub-reasons inside the function. */
            return nemR3LnxHandleInternalError(pVCpu, pRun);

        /*
         * Foreign and unknowns.
         */
        case KVM_EXIT_NMI:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_NMI on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_EPR:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_EPR on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_WATCHDOG:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_WATCHDOG on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_ARM_NISV:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_ARM_NISV on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_S390_STSI:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_S390_STSI on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_S390_TSCH:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_S390_TSCH on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_OSI:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_OSI on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_PAPR_HCALL:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_PAPR_HCALL on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_S390_UCONTROL:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_S390_UCONTROL on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_DCR:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_DCR on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_S390_SIEIC:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_S390_SIEIC on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_S390_RESET:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_S390_RESET on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_UNKNOWN:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_UNKNOWN on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        case KVM_EXIT_XEN:
            AssertLogRelMsgFailedReturn(("KVM_EXIT_XEN on VCpu #%u at %04x:%RX64!\n", pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
        default:
            AssertLogRelMsgFailedReturn(("Unknown exit reason %u on VCpu #%u at %04x:%RX64!\n", pRun->exit_reason, pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip), VERR_NEM_IPE_1);
    }

    RT_NOREF(pVM, pVCpu, pRun);
    return VERR_NOT_IMPLEMENTED;
}

static VBOXSTRICTRC nemHCLnxHandleTimers(PVMCC pVM, PVMCPUCC pVCpu)
{
    uint64_t nsAbsNextTimerEvt;
    uint64_t uTscNow;
    uint64_t nsDelta = TMVirtualSyncGetNsToDeadline(pVM, &nsAbsNextTimerEvt, &uTscNow);

    [[maybe_unused]] uint64_t const nsAbsOldTimerEvt = pVCpu->nem.s.nsAbsNextTimerEvt;

    pVCpu->nem.s.nsAbsNextTimerEvt = nsAbsNextTimerEvt;

    /*
     * With this optimization we only program timers once when something changes. We can enable this when we are
     * confident that everything works correctly.
     */
#ifdef VBOX_KVM_DONT_REPROGRAM_TIMERS
    if (nsAbsOldTimerEvt == nsAbsNextTimerEvt) {
        return VINF_SUCCESS;
    }
#endif

    if (nsDelta == 0) {
        /* If there is no timeout, program a catch-all timer instead. */
        nsDelta = RT_NS_1MS_64;
    } else if (nsDelta >= RT_NS_1SEC_64) {
        /* We need to exit at least once every 4 seconds. */
        nsDelta = RT_NS_1SEC_64;
    }

    struct itimerspec timeout {};

    /*
     * It would be nice to program absolute timeouts here instead for better accuracy, but VBox times do not correlate
     * to any Linux timer.
     */
    timeout.it_value.tv_sec = nsDelta / RT_NS_1SEC_64;
    timeout.it_value.tv_nsec = nsDelta % RT_NS_1SEC_64;

    int rcTimer = timer_settime(pVCpu->nem.s.pTimer, 0 /* relative timeout */,
                                    &timeout, nullptr);
    AssertLogRel(rcTimer == 0);

    return VINF_SUCCESS;
}

static VBOXSTRICTRC nemHCLnxCheckAndInjectInterrupts(PVMCPUCC pVCpu)
{
#ifdef VBOX_WITH_KVM_IRQCHIP_FULL
    NOREF(pVCpu);
    AssertLogRelMsg(!TRPMHasTrap(pVCpu), ("TRPM has trap but full irqchip is enabled"));
    return VINF_SUCCESS;
#else
    if (TRPMHasTrap(pVCpu))
    {
        TRPMEVENT enmType = TRPM_32BIT_HACK;
        uint8_t   bTrapNo = 0;
        TRPMQueryTrap(pVCpu, &bTrapNo, &enmType);
        Log(("nemHCLnxCheckAndInjectInterrupts: Pending trap: bTrapNo=%#x enmType=%d\n", bTrapNo, enmType));
        if (enmType == TRPM_HARDWARE_INT)
        {
            struct kvm_interrupt kvm_int;
            RT_ZERO(kvm_int);
            kvm_int.irq = bTrapNo;
            int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_INTERRUPT, &kvm_int);
            AssertLogRelMsgReturn(rcLnx == 0, ("rcLnx=%d errno=%d\n", rcLnx, errno), VERR_NEM_IPE_5);

            TRPMResetTrap(pVCpu);
        }
        else
        {
            return VERR_NOT_SUPPORTED;
        }

    }
    return VINF_SUCCESS;
#endif
}

VBOXSTRICTRC nemR3NativeRunGC(PVM pVM, PVMCPU pVCpu)
{
    /*
     * Try switch to NEM runloop state.
     */
    if (VMCPU_CMPXCHG_STATE(pVCpu, VMCPUSTATE_STARTED_EXEC_NEM, VMCPUSTATE_STARTED))
    { /* likely */ }
    else
    {
        VMCPU_CMPXCHG_STATE(pVCpu, VMCPUSTATE_STARTED_EXEC_NEM, VMCPUSTATE_STARTED_EXEC_NEM_CANCELED);
        LogFlow(("NEM/%u: returning immediately because canceled\n", pVCpu->idCpu));
        return VINF_SUCCESS;
    }

    /*
     * The first time we come here, we have to apply Spectre mitigations. The prctl interface only allows us to set
     * these only for the current thread.
     */
    if (!pVCpu->nem.s.fMitigationsApplied) {
        Log(("NEM/%u: applying mitigations\n", pVCpu->idCpu));
        if (pVM->hm.s.fIbpbOnVmEntry || pVM->hm.s.fIbpbOnVmExit) {
            int rcLnx = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);

            if (rcLnx != 0 && errno == EPERM) {
                LogRel(("WARNING: requested IBPB, but kernel API is not activated! Boot Linux with spectre_v2_user=prctl.\n", pVCpu->idCpu));
            } else {
                AssertLogRelMsgReturn(rcLnx == 0,
                                      ("rcLnx=%d errno=%d\n", rcLnx, errno),
                                      VERR_NEM_MISSING_KERNEL_API_1);
                Log(("NEM/%u: enabled IBPB\n", pVCpu->idCpu));
            }
        }

        pVCpu->nem.s.fMitigationsApplied = true;
    }

    /*
     * The run loop.
     */
    struct kvm_run * const  pRun                = pVCpu->nem.s.pRun;
    const bool              fSingleStepping     = DBGFIsStepping(pVCpu);
    VBOXSTRICTRC            rcStrict            = VINF_SUCCESS;
    bool                    fStatefulExit       = false;  /* For MMIO and IO exits. */
    for (unsigned iLoop = 0;; iLoop++)
    {
        /*
         * Pending interrupts or such?  Need to check and deal with this prior
         * to the state syncing.
         */
        if (VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_INTERRUPT_APIC | VMCPU_FF_UPDATE_APIC | VMCPU_FF_INTERRUPT_PIC
                                     | VMCPU_FF_INTERRUPT_NMI  | VMCPU_FF_INTERRUPT_SMI))
        {
            /* Try inject interrupt. */
            rcStrict = nemHCLnxHandleInterruptFF(pVM, pVCpu, pRun);
            if (rcStrict == VINF_SUCCESS)
            { /* likely */ }
            else
            {
                LogFlow(("NEM/%u: breaking: nemHCLnxHandleInterruptFF -> %Rrc\n", pVCpu->idCpu, VBOXSTRICTRC_VAL(rcStrict) ));
                STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatBreakOnStatus);
                break;
            }
        }

    // See NEMR3CanExecuteGuest for details why we ignore A20 at this point.
#ifndef VBOX_WITH_KVM_IRQCHIP_FULL
        /*
         * Do not execute in KVM if the A20 isn't enabled.
         */
        if (PGMPhysIsA20Enabled(pVCpu))
        { /* likely */ }
        else
        {
            rcStrict = VINF_EM_RESCHEDULE_REM;
            LogFlow(("NEM/%u: breaking: A20 disabled\n", pVCpu->idCpu));
            break;
        }
#endif

        /*
         * Ensure KVM has the whole state.
         */
        if ((pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_ALL) != CPUMCTX_EXTRN_ALL)
        {
            int rc2 = nemHCLnxExportState(pVM, pVCpu, &pVCpu->cpum.GstCtx, pRun);
            AssertRCReturn(rc2, rc2);
        }

        /* Poll timers and run for a bit. */
        nemHCLnxHandleTimers(pVM, pVCpu);

        if (   !VM_FF_IS_ANY_SET(pVM, VM_FF_EMT_RENDEZVOUS | VM_FF_TM_VIRTUAL_SYNC)
            && !VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_HM_TO_R3_MASK))
        {
            if (VMCPU_CMPXCHG_STATE(pVCpu, VMCPUSTATE_STARTED_EXEC_NEM_WAIT, VMCPUSTATE_STARTED_EXEC_NEM))
            {
                LogFlow(("NEM/%u: Entry @ %04x:%08RX64 IF=%d EFL=%#RX64 SS:RSP=%04x:%08RX64 cr0=%RX64\n",
                         pVCpu->idCpu, pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip,
                         !!(pRun->s.regs.regs.rflags & X86_EFL_IF), pRun->s.regs.regs.rflags,
                         pRun->s.regs.sregs.ss.selector, pRun->s.regs.regs.rsp, pRun->s.regs.sregs.cr0));

                VBOXSTRICTRC rc2 = nemHCLnxCheckAndInjectInterrupts(pVCpu);
                AssertLogRelMsg(RT_SUCCESS(rc2), ("Failed to inject interrupt"));

                TMNotifyStartOfExecution(pVM, pVCpu);

#ifdef VBOX_WITH_KVM_NESTING
                AssertReleaseMsg(not (pVCpu->nem.s.nestedGuestActive and pRun->kvm_dirty_regs),
                            ("Bug: Nested guest actitive and dirty regs are set: %x", pRun->kvm_dirty_regs));
#endif

                int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_RUN, 0UL);
                int errno_ = errno;

                VMCPU_CMPXCHG_STATE(pVCpu, VMCPUSTATE_STARTED_EXEC_NEM, VMCPUSTATE_STARTED_EXEC_NEM_WAIT);
                TMNotifyEndOfExecution(pVM, pVCpu, ASMReadTSC());

                pVCpu->nem.s.pRun->immediate_exit = 0;

#ifdef LOG_ENABLED
                if (LogIsFlowEnabled())
                {
                    struct kvm_mp_state MpState = {UINT32_MAX};
                    ioctl(pVCpu->nem.s.fdVCpu, KVM_GET_MP_STATE, &MpState);
                    LogFlow(("NEM/%u: Exit  @ %04x:%08RX64 IF=%d EFL=%#RX64 CR8=%#x Reason=%#x IrqReady=%d Flags=%#x %#lx\n", pVCpu->idCpu,
                             pRun->s.regs.sregs.cs.selector, pRun->s.regs.regs.rip, pRun->if_flag,
                             pRun->s.regs.regs.rflags, pRun->s.regs.sregs.cr8, pRun->exit_reason,
                             pRun->ready_for_interrupt_injection, pRun->flags, MpState.mp_state));
                }
#endif
                fStatefulExit = false;
                if (RT_LIKELY(rcLnx == 0 || errno_ == EINTR))
                {
#ifdef VBOX_WITH_KVM_NESTING
                    if (pRun->exit_reason == KVM_EXIT_INTR) {
                        pVCpu->nem.s.nestedGuestActive = KvmIsNestedGuestExit(pVM, pVCpu);
                    } else {
                        pVCpu->nem.s.nestedGuestActive = false;
                    }
#endif
                    /*
                     * Deal with the exit.
                     */
                    rcStrict = nemHCLnxHandleExit(pVM, pVCpu, pRun, &fStatefulExit);
                    if (rcStrict == VINF_SUCCESS)
                    { /* hopefully likely */ }
                    else
                    {
                        LogFlow(("NEM/%u: breaking: nemHCLnxHandleExit -> %Rrc\n", pVCpu->idCpu, VBOXSTRICTRC_VAL(rcStrict) ));
                        STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatBreakOnStatus);
                        break;
                    }
                }
                else if (errno_ == EAGAIN) {
                    /*
                    * We might drop out of KVM_RUN if the vCPU is still in an
                    * uninitialized state (e.g. WAIT_FOR_INIT) and some spurious
                    * wakeup event is received. In this case, simply do nothing
                    * and let the run loop enter KVM_RUN again.
                    * See https://elixir.bootlin.com/linux/v6.6/source/arch/x86/kvm/x86.c#L11138
                    */
                }
                else
                {
                    rc2 = RTErrConvertFromErrno(errno_);
                    AssertLogRelMsgFailedReturn(("KVM_RUN failed: rcLnx=%d errno=%u rc=%Rrc\n", rcLnx, errno_, rc2), rc2);
                }

                /*
                 * If no relevant FFs are pending, loop.
                 */
                if (   !VM_FF_IS_ANY_SET(   pVM,   !fSingleStepping ? VM_FF_HP_R0_PRE_HM_MASK    : VM_FF_HP_R0_PRE_HM_STEP_MASK)
                    && !VMCPU_FF_IS_ANY_SET(pVCpu, !fSingleStepping ? VMCPU_FF_HP_R0_PRE_HM_MASK : VMCPU_FF_HP_R0_PRE_HM_STEP_MASK) )
                { /* likely */ }
                else
                {

                    /** @todo Try handle pending flags, not just return to EM loops.  Take care
                     *        not to set important RCs here unless we've handled an exit. */
                    LogFlow(("NEM/%u: breaking: pending FF (%#x / %#RX64)\n",
                             pVCpu->idCpu, pVM->fGlobalForcedActions, (uint64_t)pVCpu->fLocalForcedActions));
                    STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatBreakOnFFPost);
                    break;
                }
            }
            else
            {
                LogFlow(("NEM/%u: breaking: canceled %d (pre exec)\n", pVCpu->idCpu, VMCPU_GET_STATE(pVCpu) ));
                STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatBreakOnCancel);
                break;
            }
        }
        else
        {
            LogFlow(("NEM/%u: breaking: pending FF (pre exec)\n", pVCpu->idCpu));
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatBreakOnFFPre);
            break;
        }
    } /* the run loop */


    /*
     * If the last exit was stateful, commit the state we provided before
     * returning to the EM loop so we have a consistent state and can safely
     * be rescheduled and whatnot.  This may require us to make multiple runs
     * for larger MMIO and I/O operations. Sigh^3.
     *
     * Note! There is no 'ing way to reset the kernel side completion callback
     *       for these stateful i/o exits.  Very annoying interface.
     */
    /** @todo check how this works with string I/O and string MMIO. */
    if (fStatefulExit && RT_SUCCESS(rcStrict))
    {
        STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatFlushExitOnReturn);
        uint32_t const uOrgExit = pRun->exit_reason;
        for (uint32_t i = 0; ; i++)
        {
            pRun->immediate_exit = 1;
            int rcLnx = ioctl(pVCpu->nem.s.fdVCpu, KVM_RUN, 0UL);
            Log(("NEM/%u: Flushed stateful exit -> %d/%d exit_reason=%d\n", pVCpu->idCpu, rcLnx, errno, pRun->exit_reason));
            if (rcLnx == -1 && errno == EINTR)
            {
                switch (i)
                {
                    case 0: STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatFlushExitOnReturn1Loop); break;
                    case 1: STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatFlushExitOnReturn2Loops); break;
                    case 2: STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatFlushExitOnReturn3Loops); break;
                    default: STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatFlushExitOnReturn4PlusLoops); break;
                }
                break;
            }
            AssertLogRelMsgBreakStmt(rcLnx == 0 && pRun->exit_reason == uOrgExit,
                                     ("rcLnx=%d errno=%d exit_reason=%d uOrgExit=%d\n", rcLnx, errno, pRun->exit_reason, uOrgExit),
                                     rcStrict = VERR_NEM_IPE_6);
            VBOXSTRICTRC rcStrict2 = nemHCLnxHandleExit(pVM, pVCpu, pRun, &fStatefulExit);
            if (rcStrict2 == VINF_SUCCESS || rcStrict2 == rcStrict)
            { /* likely */ }
            else if (RT_FAILURE(rcStrict2))
            {
                rcStrict = rcStrict2;
                break;
            }
            else
            {
                AssertLogRelMsgBreakStmt(rcStrict == VINF_SUCCESS,
                                         ("rcStrict=%Rrc rcStrict2=%Rrc\n", VBOXSTRICTRC_VAL(rcStrict), VBOXSTRICTRC_VAL(rcStrict2)),
                                         rcStrict = VERR_NEM_IPE_7);
                rcStrict = rcStrict2;
            }
        }
        pRun->immediate_exit = 0;
    }

    /*
     * If the CPU is running, make sure to stop it before we try sync back the
     * state and return to EM.  We don't sync back the whole state if we can help it.
     */
    if (!VMCPU_CMPXCHG_STATE(pVCpu, VMCPUSTATE_STARTED, VMCPUSTATE_STARTED_EXEC_NEM))
        VMCPU_CMPXCHG_STATE(pVCpu, VMCPUSTATE_STARTED, VMCPUSTATE_STARTED_EXEC_NEM_CANCELED);

    if (pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_ALL)
    {
        /* Try anticipate what we might need. */
        uint64_t fImport = CPUMCTX_EXTRN_INHIBIT_INT | CPUMCTX_EXTRN_INHIBIT_NMI /* Required for processing APIC,PIC,NMI & SMI FFs. */
                         | IEM_CPUMCTX_EXTRN_MUST_MASK /*?*/;
        if (   (rcStrict >= VINF_EM_FIRST && rcStrict <= VINF_EM_LAST)
            || RT_FAILURE(rcStrict))
            fImport = CPUMCTX_EXTRN_ALL;
# ifdef IN_RING0 /* Ring-3 I/O port access optimizations: */
        else if (   rcStrict == VINF_IOM_R3_IOPORT_COMMIT_WRITE
                 || rcStrict == VINF_EM_PENDING_R3_IOPORT_WRITE)
            fImport = CPUMCTX_EXTRN_RIP | CPUMCTX_EXTRN_CS | CPUMCTX_EXTRN_RFLAGS;
        else if (rcStrict == VINF_EM_PENDING_R3_IOPORT_READ)
            fImport = CPUMCTX_EXTRN_RAX | CPUMCTX_EXTRN_RIP | CPUMCTX_EXTRN_CS | CPUMCTX_EXTRN_RFLAGS;
# endif
        else if (VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_INTERRUPT_PIC | VMCPU_FF_INTERRUPT_APIC
                                          | VMCPU_FF_INTERRUPT_NMI | VMCPU_FF_INTERRUPT_SMI))
            fImport |= IEM_CPUMCTX_EXTRN_XCPT_MASK;

        if (pVCpu->cpum.GstCtx.fExtrn & fImport)
        {
            int rc2 = nemHCLnxImportState(pVCpu, fImport, &pVCpu->cpum.GstCtx, pRun);
            if (RT_SUCCESS(rc2))
                pVCpu->cpum.GstCtx.fExtrn &= ~fImport;
            else if (RT_SUCCESS(rcStrict))
                rcStrict = rc2;
            if (!(pVCpu->cpum.GstCtx.fExtrn & CPUMCTX_EXTRN_ALL))
                pVCpu->cpum.GstCtx.fExtrn = 0;
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatImportOnReturn);
        }
        else
            STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatImportOnReturnSkipped);
    }
    else
    {
        pVCpu->cpum.GstCtx.fExtrn = 0;
        STAM_REL_COUNTER_INC(&pVCpu->nem.s.StatImportOnReturnSkipped);
    }

    LogFlow(("NEM/%u: %04x:%08RX64 efl=%#08RX64 => %Rrc\n", pVCpu->idCpu, pVCpu->cpum.GstCtx.cs.Sel, pVCpu->cpum.GstCtx.rip,
             pVCpu->cpum.GstCtx.rflags.u, VBOXSTRICTRC_VAL(rcStrict) ));
    return rcStrict;
}


/** @page pg_nem_linux NEM/linux - Native Execution Manager, Linux.
 *
 * This is using KVM.
 *
 */
