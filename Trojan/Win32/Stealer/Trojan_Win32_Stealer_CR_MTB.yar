
rule Trojan_Win32_Stealer_CR_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 9e 06 00 00 74 12 40 3d f6 74 13 01 89 44 24 10 0f 8c } //01 00 
		$a_01_1 = {3d ee 75 37 00 7f 10 40 3d f6 ea 2b 33 89 44 24 10 0f 8c } //02 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //02 00  IsDebuggerPresent
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}