
rule Trojan_Win64_Dridex_ZR_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00 
		$a_01_1 = {52 75 6e 4f 62 6a 65 63 74 } //01 00 
		$a_01_2 = {48 75 72 61 43 61 78 74 63 73 62 54 73 79 73 6c } //01 00 
		$a_01_3 = {4a 75 6f 74 75 6a 4d 6d 67 4b 68 73 6e 79 6e 7a 73 } //01 00 
		$a_01_4 = {56 6d 69 68 65 76 67 45 61 75 79 6b 6b 61 6e 72 } //01 00 
		$a_01_5 = {57 68 6d 6e 71 61 67 73 63 6d 75 46 61 6e 65 64 73 72 43 6f 77 6d 62 79 62 74 6d } //00 00 
	condition:
		any of ($a_*)
 
}