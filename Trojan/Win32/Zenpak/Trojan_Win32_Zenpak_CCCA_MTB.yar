
rule Trojan_Win32_Zenpak_CCCA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 31 64 58 76 41 34 72 6c 54 7a 5f 51 43 4c 6b 2f 44 21 6e 43 62 71 64 32 47 66 58 2f 6a 44 2e 70 64 62 } //01 00 
		$a_01_1 = {49 65 68 68 7a 72 66 4c 69 65 65 72 61 74 69 } //01 00 
		$a_01_2 = {61 6e 65 6f 68 65 33 31 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}