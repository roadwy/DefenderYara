
rule Trojan_BAT_AgentTesla_EMM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 0b 07 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 0b 07 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 0c 08 90 00 } //01 00 
		$a_01_1 = {00 49 44 65 66 65 72 72 65 64 00 } //01 00 
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //01 00  䘀潲䉭獡㙥匴牴湩g
		$a_01_3 = {00 54 77 6f 44 69 67 69 74 59 65 61 72 4d 61 78 00 } //01 00 
		$a_01_4 = {00 4d 65 73 73 61 67 65 44 61 74 61 00 } //01 00 
		$a_01_5 = {00 47 65 74 54 79 70 65 } //01 00  䜀瑥祔数
		$a_01_6 = {00 43 6c 65 61 6e 75 70 00 } //01 00 
		$a_01_7 = {61 00 62 00 6f 00 75 00 74 00 } //00 00  about
	condition:
		any of ($a_*)
 
}