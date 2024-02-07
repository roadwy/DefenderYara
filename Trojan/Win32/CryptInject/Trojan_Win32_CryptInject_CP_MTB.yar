
rule Trojan_Win32_CryptInject_CP_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 9e 06 00 00 74 12 40 3d f6 74 13 01 89 44 24 1c 0f 8c } //01 00 
		$a_01_1 = {8b 44 24 14 40 3d c7 de 80 00 89 44 24 14 0f 8c } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}