
rule Trojan_BAT_AgentTesla_DLB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {fe 0c 02 00 20 00 00 00 00 73 90 01 03 0a fe 0e 03 00 fe 0c 03 00 73 90 01 03 0a fe 0e 04 00 fe 0c 04 00 6f 90 01 03 0a fe 0e 01 00 dd 90 01 04 fe 0c 04 00 39 90 01 04 fe 0c 04 00 6f 90 01 03 0a dc fe 0c 03 00 39 90 01 04 fe 0c 03 00 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_1 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //01 00  䘀潲䉭獡㙥匴牴湩g
		$a_01_2 = {00 44 65 63 6f 6d 70 72 65 73 73 53 74 72 69 6e 67 00 } //01 00  䐀捥浯牰獥即牴湩g
		$a_01_3 = {00 47 5a 69 70 53 74 72 65 61 6d 00 } //01 00  䜀楚印牴慥m
		$a_01_4 = {00 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 00 } //01 00 
		$a_01_5 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}