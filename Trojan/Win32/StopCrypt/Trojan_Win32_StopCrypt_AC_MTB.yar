
rule Trojan_Win32_StopCrypt_AC_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d a1 06 00 00 0f 84 90 02 04 83 f9 90 01 01 0f 84 90 02 04 40 3d 86 76 13 01 89 44 24 10 0f 8c 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}