#### 2. Luna_1.4.2.7.apk

*   **检测原理**：此应用专注于检测 Magisk 环境，采用了多种技术来识别 Magisk 的存在，包括文件和环境检测、挂载点分析、进程隔离检测以及Native方法调用。

*   **检测细节**：
    *   **Magisk 特征文件和环境变量检测**：
        *   检查环境变量中是否存在 `magisk/su` 文件。
        *   检查 `.magisk` 文件或目录。
        *   `Magisk Alpha b7ca73f4-alpha - Rule Path` 等字符串暗示它在寻找特定版本的 Magisk 或其规则路径。
    *   **挂载点分析 (`/proc/mounts`)**：
        *   通过分析 `/proc/mounts` 文件来检测与 Magisk 相关的挂载点。Magisk 通常通过修改挂载点来隐藏自身或实现模块功能。
        *   `Error checking /proc/mounts for magisk` 字符串表明它会尝试读取并分析该文件。
    *   **子进程隔离检测 (Native)**：
        *   应用会创建一个 Native 独立的子进程，以避免被针对主进程的隐藏模块所规避。
        *   在子进程中，它会再次使用 JNI 反射等方法来检测 Magisk 的痕迹。
    *   **MAC 地址异常检测**：
        *   `magiskmac()` 方法可能用于检测 Magisk 伪造的 MAC 地址或网络配置中的异常，这有时是Magisk模块的行为。
        *   相关的中文字符串 `magiskmac检测到MAC地址异常` 进一步证实了这一点。
    *   **Zygote 注入痕迹检测**：
        *   检测 `attr_prev` 是否包含 `zygote` 字符串，这可能指示 Magisk 进行了 Zygote 注入，这是 Magisk 在系统层面进行Hook的常见方式。
        *   相关中文字符串 `attr_prev包含zygote，可能是Magisk注入` 明确指出了这一检测点。
    *   **Native 方法调用**：
        *   存在 `native magiskmac()Z`, `native magisks(Ljava/lang/String;)Ljava/lang/String;`, `native rustmagisk()Z` 等方法，表明它调用了 Native 代码来执行更深层次的 Magisk 检测。
    *   **Native `magiskmac()` 方法详细分析**：
        该函数是一个高度复杂的 Native Root 检测函数，其核心在于**通过底层 Netlink 套接字与 Linux 内核进行网络接口信息的交互，并对获取到的网络接口属性（包括 MAC 地址和接口名称）进行深入分析。**
        具体检测细节可能包括：
        *   **Netlink 通信获取网络接口信息**：它不依赖于 Java 层的网络 API，而是直接通过 Netlink 套接字（`AF_NETLINK`, `NETLINK_ROUTE`）与内核通信，获取更原始、更难被 Hook 的网络接口数据。
        *   **MAC 地址伪造检测**：`magiskmac` 的函数名和对网络接口属性的分析强烈暗示它在检测网络接口的 MAC 地址是否被伪造。Root 工具（尤其是 Magisk）经常会伪造 MAC 地址来绕过设备认证或进行设备指纹欺骗。
        *   **虚拟网络接口检测**：通过分析网络接口名称和属性，它可能试图识别由 Root 工具创建的虚拟网络接口，以隐藏真实的网络环境。
        *   **SELinux 上下文检查（间接）**：虽然没有直接的 SELinux 字符串，但对 `__errno` 的检查以及复杂的条件逻辑，可能间接关联到在 Root 环境下 SELinux 策略被修改导致的网络操作错误。
        *   **混淆和反逆向工程**：大量的局部变量、复杂的条件跳转以及 `x.XXX`, `y.XXX` 这样的混淆变量名，都增加了逆向分析的难度。
    *   **Native `magisks()` 方法详细分析**：
        该函数是一个高度混淆且功能复杂的 Native Root 检测函数。它很可能实现了以下一种或多种检测机制，专注于发现 Magisk 的各种痕迹：
        *   **文件系统深度遍历和内容分析**：读取和解析 Android 文件系统中的敏感文件和目录（例如，`/proc/self/mounts`、`/data/adb`、Magisk 模块目录等），寻找 Root 相关的字符串、配置文件或异常条目。
        *   **进程环境检查**：通过系统调用或读取 `/proc` 文件系统来获取进程列表和进程信息，识别 Root 相关进程（如 `magiskd`）或异常的进程环境。
        *   **命令执行结果分析**：尝试执行一些 Root 相关的命令，并分析其输出，例如 `su` 命令的返回值或 `magisk` 命令的输出。
        *   **时间戳和日志异常**：结合时间戳和日志记录，可能用于检测 Root 环境下常见的日志篡改或不寻常的时间行为。
        *   **高强度混淆**：为了对抗逆向分析，该函数采用了复杂的控制流混淆、常量混淆以及可能的函数指针调用，使得静态分析非常困难。
    *   **Native `rustmagisk()` 方法详细分析**：
        该函数是 `Luna_1.4.2.7.apk` 中一个功能强大的 Native Root 检测函数，其核心是**通过执行 shell 命令并分析其输出来识别 Magisk 的存在。**
        具体检测细节可能包括：
        *   **执行与 Magisk 相关的 shell 命令**：该函数利用 `popen()` 执行外部 shell 命令，并期望这些命令能够暴露出 Magisk 的特定行为、文件或进程。这些命令可能包括查询 Magisk 状态、查找 `su` 二进制文件、检查关键目录（如 `/data/adb`）或分析 `/proc/mounts`。
        *   **命令输出解析与关键词匹配**：通过 `fgets()` 读取命令输出，并使用 `strstr()` 等字符串函数在输出中搜索 Root 相关的关键词或模式。
        *   **系统属性验证**：通过 `__system_property_get()` 获取系统属性，并将其与预期值进行比较，以检测被 Root 环境篡改的系统属性。
        *   **日志记录和混淆**：检测过程中的关键步骤和结果会通过 `__android_log_print` 进行详细记录。同时，函数内部的复杂控制流和混淆技术旨在增加逆向分析的难度。
    *   **Native `checksuskernel()` 方法详细分析**：
        该函数 `checksuskernel`（检查可疑内核）旨在通过检查特定文件或目录的属性来检测 Root 和内核篡改。它的主要检测逻辑如下：
        *   **文件系统属性检查 (`stat`)**：它尝试获取文件 `/proc/fs/ext4` 的状态信息。这个文件通常用于反映内核对 ext4 文件系统的支持情况。对它的存在、权限和元数据的检查是 Root 检测的常见手段。`s__proc_fs_ext4_00140650` 看起来代表文件路径 `"/proc/fs/ext4"`。
        *   **`st_nlink` 属性值比对**：它会读取 `/proc/fs/ext4` 的 `st_nlink`（硬链接数）属性，并将其与一个硬编码的预期值 `0x16d` 进行比较。如果这个值不匹配，很可能表示 Root 工具已经篡改了内核或文件系统结构，或者这是一个伪造的文件系统。
        *   **日志记录和返回标志**：检测到异常时，会记录日志并返回一个标志（1），表示检测失败或发现可疑行为。
        *   **高强度混淆**：通过复杂的控制流和不透明谓词 (`x.620`, `y.621`) 来混淆逻辑，增加逆向分析的难度。
    *   **Native `procscan()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_procscan` 函数（进程扫描）是一个非常典型的 Root 检测函数，它通过遍历 `/proc` 文件系统中的进程信息来寻找 Root 相关的进程、文件或挂载点异常。它的主要检测逻辑如下：
        *   **硬编码敏感字符串的初始化**：函数内部硬编码了一系列与 Root 工具、修改框架和敏感文件路径相关的字符串，包括：
            *   `"dex2oat"` (可能被 Root 篡改)
            *   `"APatch"` (新型 Root 方案)
            *   `"lsposed"` (Xposed 框架的继任者)
            *   `"_magisk"` (Magisk Root)
            *   `"shamiko"` (Magisk Root 隐藏模块)
            *   `"/proc/mounts"`
            *   `"/proc/self/mounts"`
            *   `"/proc/self/mountinfo"`
        *   **进程信息扫描 (`fopen`, `fgets`, `fclose`)**：它通过 `fopen()` 打开并使用 `fgets()` 读取 `/proc` 文件系统下各个进程的敏感文件（例如 `/proc/<PID>/status`, `/proc/<PID>/cmdline`, `/proc/<PID>/mounts`）。
        *   **关键词匹配 (`strstr`)**：在读取到的进程信息或文件内容中搜索上述硬编码的敏感关键词，尤其是 `"overlay"`（与 Magisk 的 `overlayfs` 机制相关）。
        *   **文件存在和可读性检查 (`access`)**：通过 `access()` 函数检查敏感文件或目录是否存在以及是否可访问。
        *   **日志记录**：详细记录检测过程中的关键信息，包括发现的关键词、文件打开失败等。
        *   **高强度混淆**：与之前的函数一样，使用了大量的控制流混淆和不透明谓词 (`x.626`, `y.627`) 来隐藏逻辑。
    *   **Native `findlsp()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_findlsp` 函数（查找 LSP）的名称直接表明了它旨在检测 LSPosed (或 Xposed) 框架。LSPosed 是一个强大的 Hook 框架，常用于 Root 设备，因此检测它的存在是 Root/篡改检测的重要组成部分。
        主要检测逻辑如下：
        *   **系统属性 `ro.dalvik.vm.native.bridge` 检查**：核心检测点是使用 `__system_property_get()` 获取名为 `"ro.dalvik.vm.native.bridge"` 的系统属性。Xposed/LSPosed 等 Hook 框架经常会利用或修改这个属性，例如将其指向自己的 Native 库，以实现在 Dalvik/ART 启动时进行 Hook。
        *   **属性值分析**：如果该属性存在且有值，函数会尝试将其值转换为整数 (`atoi`) 并与 1 进行比较。这可能是在寻找一个特定的数字标识符，或者检测该属性是否指向一个非预期的、由 Hook 框架提供的 Native 库。异常的属性值将导致函数返回 0，表示检测到 Hook 框架。
        *   **日志记录**：函数会打印日志 (`__android_log_print`) 来记录检测过程和结果。
        *   **高强度混淆**：与之前分析的函数一样，该函数也大量使用了复杂的控制流混淆和不透明谓词 (`x.624`, `y.625`)，以增加静态分析的难度。
    *   **Native `roots()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_roots` 函数的名称直接表明了它是一个通用的 Root 痕迹检测函数。它的逻辑复杂，涉及文件操作、时间戳、进程信息获取等多种手段，并且存在高强度混淆。
        主要检测逻辑和细节如下：
        *   **文件/目录存在性及内容检查 (`fopen`, `fgets`, `fclose`, `strstr`)**：
            *   **打开并读取文件**：尝试打开并读取某些文件，其路径可能与 Root 常用工具或相关配置文件有关（例如 `/system/bin/su`, `/system/xbin/su`, `/data/local/su` 等）。
            *   **搜索关键词**：在读取的文件内容中搜索 Root 相关的关键词，例如 `su`, `magisk`, `xposed` 或其他工具的名称。
        *   **时间戳检查 (`time`)**：获取当前时间戳，可能用于时间敏感的 Root 检测，例如检测文件创建时间、修改时间是否异常，或者防止时间回溯攻击。
        *   **进程信息获取与分析**：可能涉及遍历 `/proc` 文件系统，读取进程信息，寻找 Root 相关的守护进程或异常进程行为。
        *   **动态 API 调用**：通过函数指针调用 Native API 和库函数，增加了静态分析的难度。
        *   **高强度混淆**：该函数通过复杂的控制流、不透明谓词 (`x.578`, `y.579`) 和函数指针调用进行混淆，使得 Root 检测逻辑难以被快速识别和绕过。
    *   **Native `kernels()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_kernels` 函数的名称直接表明了它与内核（Kernel）相关的检测。它很可能旨在通过检查内核的特定行为或信息来发现 Root 或内核篡改。其伪代码延续了混淆风格，但我们仍能识别出一些关键模式：
        *   **内核版本信息检查**：通过读取 `/proc/version` 文件或执行 `uname -a` 等命令，获取设备的内核版本字符串。Root 设备上可能会运行修改过的内核版本，或者其版本字符串中包含 Root 相关的关键词。
        *   **敏感文件/目录内容分析**：读取 `/proc` 文件系统中的其他内核相关文件（如 `/proc/cmdline`, `/proc/cpuinfo`, `/proc/self/attr/current` 等），寻找 Root 相关的标识或篡改。
        *   **动态 API 调用**：函数通过函数指针动态调用 Native API 和库函数，可能用于执行文件操作、命令执行或系统属性获取。
        *   **时间戳和日志记录**：记录检测时间和过程，可能用于防止时间回溯或追踪检测路径。
        *   **高强度混淆**：通过复杂的控制流和不透明谓词 (`x.580`, `y.581`) 来混淆逻辑，增加逆向分析的难度。
    *   **Native `kerneltests()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_kerneltests` 函数的名称直接表明了它在执行与内核相关的测试，以发现 Root 或内核篡改。其伪代码延续了之前函数的复杂和混淆风格，但我们仍能识别出以下关键模式：
        *   **内核版本字符串分析**：通过读取 `/proc/version` 文件或执行 `uname -a` 等命令，获取设备的内核版本字符串。Root 设备上可能会运行修改过的内核版本，或者其版本字符串中包含 Root 相关的关键词。
        *   **敏感文件内容分析**：读取 `/proc` 文件系统中的其他内核相关文件（如 `/proc/cmdline`, `/proc/cpuinfo`, `/proc/self/attr/current` 等），寻找 Root 相关的标识或篡改。
        *   **系统属性检查**：可能通过 `__system_property_get` 等获取与内核相关的系统属性，并检查其合法性。
        *   **时间戳分析**：结合时间戳，可能用于检测文件修改时间、创建时间是否异常，或者防止时间回溯或追踪检测路径。
        *   **动态调用 Native API**：通过函数指针动态调用 Native API 和库函数，实现文件操作、命令执行或字符串处理。
        *   **高强度混淆**：通过复杂的控制流和不透明谓词 (`x.582`, `y.583`) 来混淆逻辑，增加逆向分析的难度。
    *   **Native `checkksuboot()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_checkksuboot` 函数的名称非常直接，它旨在检测 KernelSU 引导是否异常。KernelSU 是一种新型的 Root 方案，它直接在内核层进行 Hook，因此对其引导过程或相关系统属性的检测是发现 KernelSU 的关键。
        其主要检测逻辑如下：
        *   **设置系统属性 (`__system_property_set`)**：核心操作是尝试设置一个名为 `"kernel.find.log"` (或类似 `s_kernel_find_log_00140540`) 的系统属性，并将其值设置为 `"1"` (或类似 `DAT_00140550`)。这可能是一种内部机制，用于在应用或 KernelSU 引导过程中标记或共享 KernelSU 的检测状态。
        *   **日志记录 (`__android_log_print`)**：函数会打印日志，记录其设置系统属性的行为，例如消息 `"Set kernel find log to 1"`。
        *   **高强度混淆**：此函数也使用了复杂的控制流和不透明谓词 (`x.610`, `y.611`) 来混淆其逻辑。
        *   **推测**：这个函数本身可能不是一个直接的检测器，而更像是一个**标志设置器或状态报告器**，与其他更复杂的 KernelSU 检测逻辑配合使用。
    *   **Native `findksu()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_findksu` 函数的名称直接表明了它旨在**查找 KernelSU**。结合之前分析的 `checkksuboot` 函数，这个函数是 KernelSU 检测流程中的一个重要环节。
        其主要检测逻辑如下：
        *   **获取系统属性 (`__system_property_get`)**：核心功能是获取一个名为 `"kernel.find.log"` (或类似 `s_kernel_find_log_00140540`) 的特定系统属性。这与 `checkksuboot` 函数中设置的系统属性完全一致。
        *   **判断属性存在性**：如果该系统属性存在且有值（即 `__system_property_get` 返回的长度大于 0），则认为 KernelSU 存在，并返回 `true`。否则返回 `false`。
        *   **日志记录**：函数会记录获取到的系统属性值，有助于调试和追踪。
        *   **协作关系**：该函数与 `checkksuboot` 函数形成协作，`checkksuboot` 设置标志，`findksu` 查询标志，以判断 KernelSU 的存在。
    *   **Native `findauth()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_findauth` 函数的名称直接表明了它旨在**查找授权**，通常指的是 Root 权限的授权。该函数通过检查敏感文件路径和其访问权限来判断 Root 状态。
        其主要检测逻辑如下：
        *   **敏感文件路径检查**：函数硬编码了文件路径 `"/data/local/tmp/attestation"` (或类似 `s__data_local_tmp_attestation_0013ffa0`)。它使用 `access()` 系统调用来判断该文件是否存在。
        *   **Root 权限授权指示**：如果该敏感文件存在，则可能被视为 Root 权限授权或 Root 痕迹的一个指示。`"/data/local/tmp"` 目录通常是 Root 工具进行测试或留下痕迹的场所。
        *   **日志记录 (`__android_log_print`)**：函数会在检测过程中打印详细的日志信息，包括文件访问结果。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.600`, `y.601`) 来混淆逻辑，增加逆向分析的难度。
    *   **Native `getEvilModules()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_getEvilModules` 函数的名称非常具有指示性，它旨在**获取（检测）恶意模块**。在 Root 检测的语境下，这通常指的是 Magisk 模块、Xposed 模块、KernelSU 模块或其他可能用于 Root、修改或绕过安全机制的 Native 库。
        其主要检测逻辑如下：
        *   **硬编码恶意模块列表**：函数内部维护一个硬编码的字符串数组，其中包含了已知 Root 工具或修改框架（如 Magisk、Xposed、KernelSU 等）相关的模块文件名或路径。`s_libmagiskinit_so_0013d128` 提示其中可能包含 `"libmagiskinit.so"`，这是 Magisk 的一个关键组件。
        *   **遍历检测**：函数会遍历这个模块名称列表。
        *   **文件存在性/属性检查**：对于列表中的每个模块名称，函数会尝试检查其对应的文件是否存在于文件系统中，或者检查其文件属性是否异常。这可能通过 `access()` 或 `stat()` 等系统调用实现。
        *   **结果收集**：函数会将检测结果收集起来，并作为返回值返回。返回值可能是一个列表，包含了检测到的恶意模块，或者一个表示检测状态的标志。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.546`, `y.547`) 进行混淆，增加了逆向分析的难度。
    *   **Native `getDeviceIdentifiers()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_getDeviceIdentifiers` 函数的名称直接表明了它旨在**获取设备标识符**。在 Root 检测的语境下，如果设备的某些标识符被修改、伪造或无法获取，这可能是一个 Root 标志。
        其主要检测逻辑如下：
        *   **多源设备标识符收集**：
            *   **自定义系统属性 `luna.verid`**：可能用于存储或验证应用自身的设备标识信息。
            *   **Android ID (`Settings.Secure.ANDROID_ID`)**：一个常见的设备唯一标识符，在 Root 设备上容易被修改。
            *   **MediaDrm ID (`getMediaDrmId`)**：一个由 DRM 框架提供的、更难被篡改的设备标识符。Root 环境可能导致 DRM 功能受损或 ID 被伪造。
        *   **标识符完整性验证**：函数会检查这些标识符是否存在、是否能成功获取，以及其值是否符合预期。如果任何一个标识符获取失败、值异常或被篡改，都可能触发 Root 警告。
        *   **持久化和日志记录**：获取到的标识符可能被设置回 `luna.verid` 系统属性，用于持久化或后续验证。同时，详细的日志记录也帮助跟踪检测过程。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.552`, `y.553`) 进行混淆，增加了逆向分析的难度。
    *   **Native `getapps()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_getapps` 函数的名称直接表明了它旨在**获取（扫描）应用程序列表**。在 Root 检测的语境下，它会遍历设备上安装的应用程序，寻找 Root 管理器、Root 隐藏工具、Hook 框架或其他可疑应用程序的包名或特征。
        其主要检测逻辑如下：
        *   **获取 Android ID (`Settings.Secure.ANDROID_ID`)**：获取设备的 Android ID，如果获取失败或与预期不符，则可能触发 Root 警告。
        *   **获取 ContentResolver (`getContentResolver`)**：用于访问应用程序数据，包括安装的应用信息。
        *   **读取已安装的应用程序信息**：通过调用 Java 层的 `ContentResolver` 相关方法，获取设备上已安装应用程序的包名、签名或其他特征。
        *   **Root 相关应用检测**：在获取到的应用程序列表中搜索已知 Root 管理器（如 SuperSU, Magisk Manager）、Root 隐藏工具（如 RootCloak）、Hook 框架（如 Xposed/LSPosed）或虚拟环境（如 Parallel Space）的包名。
        *   **设备标识符验证**：获取设备的 Android ID，并与存储的或预期的 Android ID 进行比对 (`strcmp`)。如果两者不匹配，可能表示 Android ID 被修改或伪造。
        *   **日志记录**：详细记录检测过程中的关键信息和错误，包括 Android ID 的获取和比对结果。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.606`, `y.607`) 进行混淆，增加了逆向分析的难度。
    *   **Native `psdir()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_psdir` 函数的名称暗示它与进程 (`ps`) 和目录 (`dir`) 扫描有关。这通常是 Root 检测的重要组成部分，因为它可以通过检查 `/proc` 文件系统或查找特定目录来发现 Root 痕迹。
        其主要检测逻辑如下：
        *   **获取环境变量 (`getenv`)**：函数调用 `getenv()` 来获取一个环境变量的值，很可能是 `"PATH"`。如果环境变量不存在或为空，可能被视为异常。
        *   **硬编码敏感路径和关键词**：函数内部硬编码了 Root 检测的关键目标，例如格式字符串 `"%s/magisk"`, `"%s/su"`, `"%s/sutest"`。
        *   **目录遍历与文件检查**：如果获取到 PATH 环境变量，函数会将其解析为一系列目录，并遍历这些目录。在每个目录中，它会构造 Root 工具的可能路径（例如 `/system/bin/magisk`, `/data/local/su`）。
        *   **Root 二进制文件存在性检查 (`access`)**：使用 `access()` 系统调用检查这些 Root 工具的二进制文件是否存在。
        *   **日志记录**：详细记录检测过程，包括正在检查的目录、发现的 Root 工具等信息。例如，当发现 `su` 或 `magisk` 时，会明确打印日志。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.548`, `y.549`) 进行混淆，增加了逆向分析的难度。
    *   **Native `findapply()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_findapply` 函数的名称暗示它旨在**查找应用程序或应用相关的服务**。结合 Root 检测的上下文，它很可能在扫描系统中安装的应用程序或正在运行的服务列表，以寻找与 Root、Hook 或自动化工具相关的特定应用。
        其主要检测逻辑如下：
        *   **Accessibility Service 扫描**：通过 JNI 调用 Java API 获取系统服务 `ACCESSIBILITY_SERVICE`，然后调用 `getEnabledAccessibilityServiceList()` 获取所有已启用的辅助功能服务列表。
        *   **自动化工具识别**：在辅助功能服务列表中搜索已知自动化工具（例如 Auto.js）的包名或组件名（`s_youhu_laixijs_com_stardust_autoj_0013fab0`）。这是 Root 用户进行作弊或自动化操作的常见手段。
        *   **关键词匹配**：搜索其他与 Hook 或自动化相关的关键词（例如 `s_scene_0013fb28`）。
        *   **日志记录**：详细记录检测过程，特别是当检测到可疑服务时。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.586`, `y.587`) 进行混淆，增加了逆向分析的难度。
    *   **Native `findbootbl()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_findbootbl` 函数的名称直接表明了它旨在**查找引导加载程序 (bootloader)**。引导加载程序是系统启动的关键组件，Root 或定制 ROM 通常会修改引导加载程序以允许 Root 权限或加载定制的系统。检测引导加载程序的异常是 Root 检测的重要组成部分。
        其主要检测逻辑如下：
        *   **获取系统属性 `kernel.find.bl` (`__system_property_get`)**：核心功能是获取一个名为 `"kernel.find.bl"` (或类似 `s_kernel_find_bl_001405a0`) 的特定系统属性。这个系统属性可能由应用在 Native 层设置，或者由其他 Root 检测组件在引导阶段设置。
        *   **判断属性存在性**：如果该系统属性存在且有值（即 `__system_property_get` 返回的长度大于 0），则认为引导加载程序可能存在异常，并返回 `true`。否则返回 `false`。
        *   **日志记录**：函数会记录获取到的系统属性值，有助于调试和追踪。
        *   **推测与协作关系**：这个函数可能与 `Java_luna_safe_luna_MainActivity_checkbootbl` 函数形成协作关系，`checkbootbl` 可能负责设置这个属性，而 `findbootbl` 查询这个状态。
    *   **Native `checkbootbl()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_checkbootbl` 函数的名称非常直接，它旨在**检查引导加载程序 (bootloader)**。结合 `findbootbl` 函数的分析，这个函数是引导加载程序检测流程中的另一个重要环节。
        其主要检测逻辑如下：
        *   **设置系统属性 `kernel.find.bl` (`__system_property_set`)**：核心操作是尝试设置一个名为 `"kernel.find.bl"` (或类似 `s_kernel_find_bl_001405a0`) 的系统属性，并将其值设置为 `"1"` (或类似 `DAT_00140550`)。这可能是一种内部机制，用于在应用或引导过程中标记或共享引导加载程序的状态，尤其是在它被检测到异常时。
        *   **日志记录 (`__android_log_print`)**：函数会打印日志，记录其设置系统属性的行为，例如消息 `"Set kernel find bl to 1"`。
        *   **`checkbootbl` 和 `findbootbl` 的协作关系**：
            *   `checkbootbl` 负责在检测流程中设置 `"kernel.find.bl"` 系统属性，作为引导加载程序存在的内部标志。
            *   `findbootbl` 负责读取这个系统属性，并根据其存在性来判断引导加载程序是否被检测到异常。
    *   **Native `checkappnum()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_checkappnum` 函数的名称暗示它旨在**检查应用程序数量**。在 Root 检测的语境下，这可能意味着检查设备上安装的应用程序数量是否异常（例如，过少或过多），或者检查与 Zygote 相关的系统属性，因为 Zygote 负责创建应用程序进程，其行为在 Root 环境中可能被篡改。
        其主要检测逻辑如下：
        *   **获取系统属性 `persist.zygote.app_data_isolation` (`__system_property_get`)**：核心操作是获取名为 `"persist.zygote.app_data_isolation"` 的系统属性。这个属性与 Android Zygote 进程的应用程序数据隔离行为有关。在 Root 环境下，Zygote 进程可能会被 Hook 或修改，从而影响应用程序的数据隔离。
        *   **判断属性存在性/值**：如果该系统属性存在且有值，则可能被视为一种特定的状态（可能是正常的，也可能是异常的，取决于其具体的预期值和上下文），并返回相应的标志。
        *   **日志记录**：函数会打印日志来记录检测过程。
        *   **高强度混淆**：此函数也使用了复杂的控制流和不透明谓词 (`x.618`, `y.619`) 来混淆其逻辑。
        *   **推测**：该函数可能是在寻找 `persist.zygote.app_data_isolation` 属性是否存在或其值是否为 `0` 或 `1`。在某些 Root 方案中，为了绕过或修改应用行为，这个属性可能会被设置为禁用数据隔离。
    *   **Native `checkdns()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_checkdns` 函数的名称直接表明它旨在**检查 DNS (Domain Name System)**。在 Root 检测的语境下，DNS 劫持或 DNS 配置异常是 Root 工具或恶意软件常见的行为，可以用于重定向网络流量、绕过安全服务器或隐藏 Root 状态。
        其主要检测逻辑如下：
        *   **DNS 解析 (`getaddrinfo`)**：核心功能是调用 `getaddrinfo()` 解析一个由应用控制的特定域名（例如 `w.eydata.net`）。
        *   **IP 地址比对**：将解析到的 IP 地址与一个硬编码的预期 IP 地址 (`DAT_0013f8d8`) 进行字符串比较。
        *   **DNS 劫持检测**：如果解析到的 IP 地址与预期不符，则强烈暗示存在 DNS 劫持。DNS 劫持是 Root 用户或恶意软件绕过安全检查、重定向流量或进行中间人攻击的常见手段。
        *   **错误处理和日志记录**：函数会处理 DNS 解析过程中可能出现的错误 (`gai_strerror`)，并记录详细的日志信息。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.584`, `y.585`) 来混淆逻辑。
    *   **Native `checknum()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_checknum` 函数的名称暗示它旨在**检查某个“数字”**。在 Root 检测的语境下，这通常指的是系统版本号、构建号、安全补丁级别、或者其他与系统完整性相关的数字标识符。
        其主要检测逻辑如下：
        *   **获取系统属性 `persist.sys.vold_app_data_isolation` (`__system_property_get`)**：核心操作是获取名为 `"persist.sys.vold_app_data_isolation"` 的系统属性。这个属性与 Android `vold`（Volume Daemon）服务和应用程序数据隔离有关。在 Root 环境下，`vold` 的行为或相关属性可能会被修改，从而影响存储管理和数据隔离。
        *   **判断属性存在性/值**：如果该系统属性不存在或为空，或者其值不符合预期，则可能被视为 Root 或系统异常的标志。
        *   **日志记录**：函数会记录获取到的系统属性值。
        *   **高强度混淆**：此函数也使用了复杂的控制流和不透明谓词 (`x.604`, `y.605`) 来混淆其逻辑。
        *   **推测**：该函数可能是在寻找 `persist.sys.vold_app_data_isolation` 属性是否存在或其值是否为 `0` 或 `1`。在某些 Root 方案中，为了更好地与存储交互或绕过安全限制，这个属性可能会被设置为禁用数据隔离。
        *   **Native `bootloaders()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_bootloaders` 函数的名称直接表明它与引导加载程序 (bootloader) 的检测有关。Root 或定制 ROM 通常会修改引导加载程序以允许 Root 权限或加载定制的系统，因此检测引导加载程序的异常是 Root 检测的重要组成部分。
        其主要检测逻辑如下：
        *   **引导加载程序版本/信息检查**：通过读取系统属性、文件或执行命令，获取引导加载程序版本或相关信息。Root 设备上可能会运行解锁或修改过的引导加载程序。`s_getDeviceIdentifiers_0013f700` 和 `s__version__s_0013f7f8` 等字符串常量提示了这一点。
        *   **设备标识符关联**：可能将引导加载程序信息与设备的唯一标识符进行关联或比对，以验证设备完整性。
        *   **字符串匹配和版本解析**：在获取到的引导加载程序信息中搜索 Root 相关的关键词、异常版本号或与预期值不符的字符串。
        *   **动态 API 调用**：函数通过函数指针动态调用 Native API 和库函数，实现文件操作、命令执行、字符串处理或系统属性获取。
        *   **时间戳和日志记录**：记录检测时间和过程，可能用于防止时间回溯或追踪检测路径。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.574`, `y.575`) 进行混淆，增加了逆向分析的难度。
    *   **Native `fhma()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_fhma` 函数的名称不具有直接的语义，可能是一个混淆后的名称或首字母缩写。但从其伪代码内容来看，它似乎在**检查一个特殊的系统属性文件或目录的大小**。
        其主要检测逻辑如下：
        *   **敏感文件检查**：核心功能是调用 `stat()` 函数检查 `/data/property/persistent_properties` (或类似 `s__data_property_persistent_proper_00140690`) 文件。这个文件在 Android 系统中存储重要的持久化属性，其内容和大小在 Root 环境下可能被修改。
        *   **文件存在性验证**：如果 `stat()` 调用失败（文件不存在或不可访问），则可能被视为异常。
        *   **文件大小异常检测**：函数检查该文件的大小 `st_size` 是否大于 `0x7ff` (2047 字节)。如果文件大小异常地大，可能意味着它被 Root 工具或其他恶意软件篡改或填充了额外数据。
        *   **日志记录**：函数会详细记录文件检查的过程、文件大小以及任何异常情况。
        *   **高强度混淆**：此函数也使用了复杂的控制流和常量混淆来隐藏逻辑。
    *   **Native `scanlib()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_scanlib` 函数通过**深度扫描设备上所有已安装应用程序的 Native 库目录，寻找已知 Root 工具、Hook 框架或修改模块的 Native 库文件。**
        其主要检测逻辑如下：
        *   **初始化全局标志位和检测结果**：函数会清零或初始化一系列全局变量，用于存储扫描结果或发现的恶意模块信息。
        *   **遍历所有已安装应用**：通过 JNI 调用 Java 层 `PackageManager.getInstalledApplications()` 获取所有应用的列表。
        *   **获取 Native 库路径**：对每个应用，获取其 `ApplicationInfo.nativeLibraryDir` (Native 库目录) 和 `packageName` (包名)。
        *   **扫描 Native 库文件**：使用 `opendir()` 和 `readdir()` 遍历每个应用的 Native 库目录。
        *   **硬编码恶意模块匹配**：将目录中的文件名与硬编码的已知恶意模块名称列表 (`PTR_s_libmagiskinit_so_0013d128` 包含 `"libmagiskinit.so"`) 进行比较。
        *   **记录和报告**：如果发现可疑模块，会设置全局标志位 (`DAT_00143938 = 1;`)，并存储模块名称和应用包名 (`DAT_00143939`, `DAT_00143a39`)。同时，详细打印日志 `HELLOWORLD: Found suspicious module: %s in %s`。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.588`, `y.589`) 进行混淆，增加了逆向分析的难度。
    *   **Native `callLunaversion()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_callLunaversion` 函数的名称直接表明了它旨在**调用 Luna 的版本信息**。这可能涉及获取应用的自身版本、SDK 版本，或者与这些版本信息相关的其他数据。在 Root 检测的语境下，如果版本信息被篡改、无法获取或与预期不符，这可能是一个 Root 标志。
        其主要检测逻辑如下：
        *   **应用版本信息获取**：通过调用 JNI 方法 `callLunaversionFromJNI()` 和内部 `getversion` 逻辑，获取 Luna 应用或 SDK 的版本字符串。
        *   **设备标识符获取**：调用 `getDeviceIdentifiers()` 函数获取设备唯一标识符。
        *   **数据加密**：可能对获取到的版本信息或设备标识符进行加密 (`encryptData()`)，以防止数据被中间人攻击或篡改。
        *   **时间戳和日志记录**：记录检测时间和过程，可能用于防止时间回溯或追踪检测路径。
        *   **防篡改验证**：如果版本信息被篡改、无法获取或与预期不符，或者加密/解密过程出现异常，都可能触发 Root 警告。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.568`, `y.569`) 进行混淆，增加了逆向分析的难度。
    *   **Native `getStoredVersion()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_getStoredVersion` 函数的名称直接表明了它旨在**获取存储的版本信息**。这通常指的是应用程序在本地存储的版本号，可以用于与当前运行的版本进行比对，以检测应用程序是否被篡改或回滚到旧版本。在 Root 检测的语境下，如果存储的版本信息被修改或无法获取，这可能是一个 Root 标志。
        其主要检测逻辑如下：
        *   **获取本地存储版本**：核心功能是获取一个硬编码地址 (`&DAT_00143838`) 处存储的字符串，该字符串代表了应用程序在本地保存的版本信息。
        *   **作为验证基准**：这个存储的版本信息可以被其他函数调用，并与当前运行的应用版本、从服务器获取的版本或预期的版本进行比对。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.570`, `y.571`) 进行混淆，增加了逆向分析的难度。
        *   **推测与协作关系**：这个函数获取的版本信息，很可能被 `Java_luna_safe_luna_MainActivity_updateStoredVersion` 函数设置，并被 `Java_luna_safe_luna_MainActivity_callLunaversion` 或其他版本验证函数使用。
    *   **Native `updateStoredVersion()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_updateStoredVersion` 函数的名称直接表明了它旨在**更新存储的版本信息**。这通常用于将应用的当前版本号持久化到本地存储，以便后续进行版本验证。在 Root 检测的语境下，确保版本信息不被篡改并正确存储至关重要。
        其主要检测逻辑如下：
        *   **获取版本字符串 (`param_3`)**：函数接收一个指向版本字符串的 JNI `jstring` 参数。
        *   **存储版本字符串 (`strncpy` to `DAT_00143838`)**：将传入的版本字符串复制到 Native 层的全局变量 `&DAT_00143838`。这个存储位置与 `getStoredVersion` 函数读取的位置相同。
        *   **释放资源 (`ReleaseStringUTFChars`)**：释放 JNI 字符串转换过程中分配的内存。
        *   **设置标志位**：函数将一个全局变量 `DAT_00143937` 设置为 0，可能表示版本更新操作已完成。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.572`, `y.573`) 进行混淆，增加了逆向分析的难度。
        *   **协作关系**：该函数与 `getStoredVersion` 函数紧密协作，负责写入版本信息，而 `getStoredVersion` 负责读取版本信息，以防止 Root 环境下的版本欺骗和应用降级攻击。
    *   **Native `getDetectedAppName()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_getDetectedAppName` 函数的名称直接表明了它旨在**获取检测到的应用程序名称**。结合之前的 `scanlib` 函数的分析，这个函数很可能用于返回 `scanlib` 发现的可疑应用程序的包名。
        其主要检测逻辑如下：
        *   **读取全局变量**：核心功能是读取 Native 层的全局变量 `DAT_00143a39`。
        *   **JNI 字符串转换**：将 `DAT_00143a39` 中存储的 C 风格字符串转换为 Java `String` 对象并返回给 Java 层。
        *   **作为报告机制**：这个函数是 Root 检测结果报告机制的一部分。当 `scanlib` 函数发现可疑的 Native 库时，它会将该库所属的应用程序包名存储到 `DAT_00143a39`，然后 `getDetectedAppName` 就可以将这个包名返回给 Java 层，以便应用可以采取相应的措施。
    *   **Native `getDetectedModuleName()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_getDetectedModuleName` 函数的名称直接表明了它旨在**获取检测到的模块名称**。结合之前的 `scanlib` 函数的分析，这个函数很可能用于返回 `scanlib` 发现的可疑 Native 模块的名称。
        其主要检测逻辑如下：
        *   **读取全局变量**：核心功能是读取 Native 层的全局变量 `DAT_00143939`。
        *   **JNI 字符串转换**：将 `DAT_00143939` 中存储的 C 风格字符串转换为 Java `String` 对象并返回给 Java 层。
        *   **作为报告机制**：这个函数是 Root 检测结果报告机制的一部分。当 `scanlib` 函数发现可疑的 Native 库时，它会将该模块的名称存储到 `DAT_00143939`，然后 `getDetectedModuleName` 就可以将这个模块名称返回给 Java 层。
        *   **协作关系**：这个函数与 `scanlib` 函数紧密协作，`scanlib` 负责发现可疑模块并存储其名称，而 `getDetectedModuleName` 负责将这个模块名称提供给 Java 层。它与 `getDetectedAppName` 共同构成了 `scanlib` 检测结果的报告接口。
    *   **Native `wasSuspiciousModuleDetected()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_wasSuspiciousModuleDetected` 函数的名称直接表明了它旨在**判断是否检测到可疑模块**。这个函数是一个简单的查询接口，用于检查之前复杂的 Root 检测逻辑是否发现了任何可疑之处。
        其主要检测逻辑如下：
        *   **读取全局标志位**：核心功能是读取 Native 层的全局变量 `DAT_00143938`。
        *   **作为 Root 检测结果标志**：根据 `scanlib` 函数的分析，`DAT_00143938` 在发现可疑模块时会被设置为 `1`。因此，这个函数返回 `1` 则表示已检测到可疑模块（Root 迹象），返回 `0` 则表示未检测到。
        *   **报告机制**：这个函数是 Root 检测结果报告机制的重要组成部分，允许 Java 层快速查询 Root 检测状态。
        *   **协作关系**：这个函数与 `scanlib` 函数紧密协作，`scanlib` 负责发现可疑模块并设置 `DAT_00143938` 标志位，而 `wasSuspiciousModuleDetected` 负责将这个标志位提供给 Java 层。它与 `getDetectedAppName` 和 `getDetectedModuleName` 共同构成了 `scanlib` 检测结果的完整报告接口。
    *   **Native `K0ajGz()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_K0ajGz` 的函数名称是混淆后的，但从其伪代码来看，它执行了与 `getEvilModules` 类似的功能，即**遍历一个硬编码的敏感路径列表，并将它们添加到一个集合中**。这通常用于检测设备上是否存在 Root 工具、Hook 框架或隐藏 Root 的应用。
        其主要检测逻辑如下：
        *   **初始化 JNI String 对象**：可能在创建一个 `ArrayList` 或 `HashSet` 等集合对象，用于存储检测到的敏感路径。
        *   **遍历硬编码的敏感路径列表**：函数通过索引访问一个硬编码的字符串指针数组。这个数组中存储的字符串很可能就是它要检测的敏感路径。`s__data_data_com_tsng_hidemyapplis_0013c9c8` 暗示其中可能包含 `/data/data/com.tsng.hidemyapplications`，这是 **TSG（TaiChi/太极）隐藏应用列表**相关的路径。
        *   **将敏感路径添加到集合中**：将转换后的 Java 字符串添加到集合中。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.542`, `y.543`) 进行混淆，增加了逆向分析的难度。
    *   **Native `KKajGz()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_KKajGz` 的函数名称是混淆后的，但从其伪代码来看，它与 `Java_luna_safe_luna_MainActivity_K0ajGz` 功能类似，即**遍历一个硬编码的敏感路径/字符串列表，并将它们添加到一个集合中**。这通常用于检测设备上是否存在 Root 工具、Hook 框架或其他可疑痕迹。
        其主要检测逻辑如下：
        *   **初始化 JNI String 对象**：可能在创建一个 `ArrayList` 或 `HashSet` 等集合对象，用于存储检测到的敏感路径/字符串。
        *   **遍历硬编码的敏感路径/字符串列表**：函数通过索引访问一个硬编码的字符串指针数组 (`PTR_DAT_0013ce20`)。这个数组中存储的字符串很可能就是它要检测的敏感路径、包名、文件名或关键词。
        *   **将敏感路径/字符串添加到集合中**：将转换后的 Java 字符串添加到集合中。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.544`, `y.545`) 进行混淆，增加了逆向分析的难度。
    *   **Native `wNxM8s()` 方法详细分析**：
        `Java_luna_safe_luna_MainActivity_wNxM8s` 的函数名称是混淆后的，但从其伪代码来看，它执行了与 `K0ajGz` 和 `KKajGz` 类似的功能，即**遍历一个硬编码的敏感包名列表，并将它们添加到一个集合中**。这通常用于检测设备上是否存在 Root 工具、Hook 框架或隐藏 Root 的应用。
        其主要检测逻辑如下：
        *   **初始化 JNI String 对象**：可能在创建一个 `ArrayList` 或 `HashSet` 等集合对象，用于存储检测到的敏感包名。
        *   **遍历硬编码的敏感包名列表**：函数通过索引访问一个硬编码的字符串指针数组 (`PTR_s_com_tsng_hidemyapplist_0013e840`)。这个数组中存储的字符串很可能就是它要检测的敏感应用程序包名，例如 `com.tsng.hidemyapplist`。
        *   **将敏感包名添加到集合中**：将转换后的 Java 字符串添加到集合中。
        *   **高强度混淆**：该函数通过复杂的控制流和不透明谓词 (`x.540`, `y.541`) 进行混淆，增加了逆向分析的难度。


