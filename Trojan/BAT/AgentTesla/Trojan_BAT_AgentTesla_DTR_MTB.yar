
rule Trojan_BAT_AgentTesla_DTR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 0b 07 0a 2b 00 90 00 } //01 00 
		$a_01_1 = {00 46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_01_2 = {00 54 6f 43 68 61 72 41 72 72 61 79 00 } //01 00 
		$a_01_3 = {00 53 74 72 52 65 76 65 72 73 65 00 } //00 00  匀牴敒敶獲e
	condition:
		any of ($a_*)
 
}