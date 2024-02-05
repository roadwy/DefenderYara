
rule Trojan_Win32_Zusy_MF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 52 43 54 46 2e 44 4c 4c } //01 00 
		$a_01_1 = {50 6e 68 75 62 67 79 45 63 74 79 76 } //01 00 
		$a_01_2 = {52 74 63 66 76 79 4b 6e 62 67 } //01 00 
		$a_01_3 = {54 73 78 72 64 50 6e 68 62 75 67 } //01 00 
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //01 00 
		$a_01_5 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //00 00 
	condition:
		any of ($a_*)
 
}