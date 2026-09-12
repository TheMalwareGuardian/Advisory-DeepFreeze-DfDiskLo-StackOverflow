# ***[Security Vulnerability Report] Kernel Stack Overflow in DfDiskLo.sys - Faronics Deep Freeze***

Dear Faronics Security Team,

I am contacting you to responsibly disclose a vulnerability I identified during independent security research involving **DfDiskLo.sys**, one of the kernel-mode drivers used by **Faronics Deep Freeze**.

While analyzing the driver, I discovered that sending a `DeviceIoControl()` request to the exposed device interface can reliably trigger a **kernel stack exhaustion condition** that ultimately crashes the operating system with a BSOD (`0x7F - UNEXPECTED_KERNEL_MODE_TRAP / DOUBLE_FAULT`).

I reproduced the issue multiple times on fully updated test systems and obtained identical crash signatures across all executions, confirming that the behavior is deterministic and fully reliable.

---

### **Affected Versions**

The issue was successfully reproduced on the following tested versions:

* **Deep Freeze Standard 9.00.020.5760**
* **Deep Freeze Enterprise Workstation 10.10.220.5788**

#### **Affected Component**

* **DfDiskLo.sys**

---

### **Technical Details**

From a technical perspective, the issue appears to originate from the driver's dispatch logic. During initialization, the driver registers a generic pass-through handler for the IRP major function table, including `IRP_MJ_DEVICE_CONTROL`, which is the standard entry point used by `DeviceIoControl()` from userland applications.

Instead of validating or safely handling incoming IOCTL requests, the driver forwards IRPs through `IofCallDriver()` to the next attached device object. Due to the way the device stack is attached internally through `IoAttachDeviceToDeviceStack()`, the IRP is redirected back into the same driver again, creating uncontrolled recursion.

Each recursive dispatch consumes additional kernel stack space until the thread stack is exhausted, eventually triggering a Double Fault exception and crashing the entire system.

Importantly, the specific IOCTL value itself is irrelevant. The crash occurs before any IOCTL-specific processing is performed, meaning that essentially any `DeviceIoControl()` request sent to the device is sufficient to reproduce the issue.

I would also like to clarify that, although this is technically a kernel stack overflow condition, it does not appear to be exploitable for arbitrary code execution or controlled memory corruption. The issue specifically results in denial of service through uncontrolled recursive IRP forwarding and kernel stack exhaustion.

---

### **Operational Impact**

While Administrator privileges are required to communicate directly with the device interface, the affected driver itself is properly signed and trusted by Microsoft Windows. Because of this, the driver can be loaded independently from the complete Deep Freeze installation and used on systems where the product itself is not installed.

As a result, the vulnerability is not strictly limited to fully deployed Deep Freeze environments. Once the vulnerable driver and its device interface are available, a single `DeviceIoControl()` request is sufficient to trigger an immediate system crash.

In practice, this behavior could be automated through scheduled tasks, services, startup persistence mechanisms, or other forms of automation, potentially resulting in repeated crash/reboot loops and reliable denial-of-service conditions through a trusted signed driver.

---

### **Attached Materials**

To help your team reproduce and analyze the issue more easily, I have attached a ZIP archive containing:

* A documented proof-of-concept (PoC).
* WinDbg crash analysis and debugging notes.
* A technical README explaining the root cause in more detail.

---

### **Suggested Mitigation**

Based on my analysis, adding recursion protection before forwarding IRPs through `IofCallDriver()` would prevent this type of behavior entirely. Additionally, implementing a dedicated `IRP_MJ_DEVICE_CONTROL` handler that safely validates unsupported IOCTL requests would likely mitigate the issue as well.

---

### **Severity Assessment**

Using CVSS 3.1, I estimate the vulnerability as **Medium severity** with a score around **6.0**, due to the local attack vector and Administrator privilege requirement, despite the high impact on system availability.

---

### **Disclosure Policy**

I follow a standard **90-day responsible disclosure policy** and would be happy to coordinate disclosure timelines with your team if a fix is currently being developed.

Please feel free to contact me if you need any additional information, debugging details, crash dumps, or assistance reproducing the issue. I will be glad to help however I can.

Thank you very much for your time and attention.

Best regards,

**Alejandro Vazquez Vazquez**

https://www.linkedin.com/in/vazquez-vazquez-alejandro
