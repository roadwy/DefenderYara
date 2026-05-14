
rule Trojan_Win32_VulnDriver_VGZ_MTB{
	meta:
		description = "Trojan:Win32/VulnDriver.VGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {48 61 6e 64 6c 65 49 6f 63 74 6c 3a 20 49 4f 43 54 4c 20 43 41 4c 4c 45 44 3a 20 30 78 25 78 } //1 HandleIoctl: IOCTL CALLED: 0x%x
		$a_01_1 = {48 61 6e 64 6c 65 49 6f 63 74 6c 3a 20 50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64 20 66 61 69 6c 65 64 20 77 69 74 68 20 73 74 61 74 75 73 20 30 78 25 78 } //1 HandleIoctl: PsLookupProcessByProcessId failed with status 0x%x
		$a_01_2 = {48 61 6e 64 6c 65 49 6f 63 74 6c 3a 20 55 6e 74 72 75 73 74 46 69 6c 65 20 66 61 69 6c 65 64 20 77 69 74 68 20 73 74 61 74 75 73 20 30 78 25 78 } //1 HandleIoctl: UntrustFile failed with status 0x%x
		$a_01_3 = {48 61 6e 64 6c 65 49 6f 63 74 6c 3a 20 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 42 79 50 49 44 20 66 61 69 6c 65 64 20 77 69 74 68 20 73 74 61 74 75 73 20 30 78 25 78 } //1 HandleIoctl: TerminateProcessByPID failed with status 0x%x
		$a_01_4 = {44 72 69 76 65 72 20 75 6e 6c 6f 61 64 65 64 2e } //1 Driver unloaded.
		$a_01_5 = {48 61 6e 64 6c 65 43 72 65 61 74 65 3a 20 44 65 76 69 63 65 20 6f 70 65 6e 65 64 2e } //1 HandleCreate: Device opened.
		$a_01_6 = {44 72 69 76 65 72 20 6c 6f 61 64 65 64 2e } //1 Driver loaded.
		$a_01_7 = {49 6f 66 43 6f 6d 70 6c 65 74 65 52 65 71 75 65 73 74 } //1 IofCompleteRequest
		$a_01_8 = {49 6f 43 72 65 61 74 65 44 65 76 69 63 65 } //1 IoCreateDevice
		$a_01_9 = {49 6f 43 72 65 61 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b } //1 IoCreateSymbolicLink
		$a_01_10 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65 } //1 IoDeleteDevice
		$a_01_11 = {49 6f 44 65 6c 65 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b } //1 IoDeleteSymbolicLink
		$a_00_12 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4b 00 4d 00 48 00 4c 00 50 00 44 00 52 00 56 00 } //1 \DosDevices\KMHLPDRV
		$a_00_13 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4b 00 4d 00 48 00 4c 00 50 00 44 00 52 00 56 00 } //1 \Device\KMHLPDRV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1) >=14
 
}