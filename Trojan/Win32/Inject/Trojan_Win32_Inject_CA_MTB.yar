
rule Trojan_Win32_Inject_CA_MTB{
	meta:
		description = "Trojan:Win32/Inject.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d0 88 55 90 02 04 8b 4d 90 02 04 03 4d 90 02 04 8b 55 90 02 04 83 ea 90 02 04 33 ca 66 89 4d 90 00 } //01 00 
		$a_03_1 = {03 d0 33 55 90 02 04 66 89 95 90 02 04 eb 2a 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}