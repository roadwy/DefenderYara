
rule Trojan_Win32_Zenpack_MBHK_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MBHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 75 77 61 72 61 73 61 7a 69 6d 6f 66 61 78 61 7a 69 67 65 73 65 76 75 68 75 } //01 00 
		$a_01_1 = {74 6f 6c 69 78 6f 79 75 73 6f 6a 75 78 6f 64 6f 6a 61 62 75 6e 20 74 75 77 61 63 65 6b 69 63 69 6b 65 67 65 76 6f 6a 75 63 65 66 20 68 65 64 75 78 69 6d 69 6e 61 6a 69 67 69 68 } //00 00 
	condition:
		any of ($a_*)
 
}