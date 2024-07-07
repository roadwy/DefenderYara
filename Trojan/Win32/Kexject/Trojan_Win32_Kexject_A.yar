
rule Trojan_Win32_Kexject_A{
	meta:
		description = "Trojan:Win32/Kexject.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 08 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 65 64 20 61 73 20 69 6e 6a 65 63 74 65 64 20 6b 65 72 6e 65 6c } //1 started as injected kernel
		$a_00_1 = {53 74 61 72 74 4b 65 72 6e 65 6c 41 73 49 6e 6a 65 63 74 65 64 4c 69 62 72 61 72 79 } //1 StartKernelAsInjectedLibrary
		$a_00_2 = {43 4b 65 72 6e 65 6c 49 6e 73 74 61 6c 6c 65 72 3a 3a 53 65 74 41 75 74 6f 52 75 6e 56 61 6c 75 65 } //1 CKernelInstaller::SetAutoRunValue
		$a_00_3 = {6b 65 50 72 6f 63 49 6e 6a 65 63 74 6f 72 4d 4e 61 6d 65 } //1 keProcInjectorMName
		$a_00_4 = {53 79 73 74 65 6d 5c 43 6f 72 65 32 49 6e 6e 65 72 } //1 System\Core2Inner
		$a_00_5 = {4b 65 41 70 70 6c 65 74 } //1 KeApplet
		$a_00_6 = {4b 00 65 00 72 00 6e 00 65 00 6c 00 46 00 6f 00 72 00 6b 00 } //1 KernelFork
		$a_02_7 = {54 45 4d 50 5c 6b 65 36 34 90 02 10 2e 65 78 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1) >=5
 
}