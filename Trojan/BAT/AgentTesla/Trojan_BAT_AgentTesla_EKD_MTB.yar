
rule Trojan_BAT_AgentTesla_EKD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 9a 0c 00 08 6f 90 01 03 0a 0d 16 13 04 90 02 05 09 11 04 9a 13 05 00 11 05 6f 90 01 03 0a 13 06 16 13 07 90 02 05 11 06 11 07 9a 13 08 11 08 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 13 09 11 09 90 02 05 11 08 14 14 90 00 } //01 00 
		$a_01_1 = {00 47 65 74 4d 65 74 68 6f 64 73 00 } //01 00  䜀瑥敍桴摯s
		$a_01_2 = {00 47 65 74 54 79 70 65 73 00 } //00 00  䜀瑥祔数s
	condition:
		any of ($a_*)
 
}