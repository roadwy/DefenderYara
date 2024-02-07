
rule Trojan_BAT_AgentTesla_EFH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 09 17 58 0d 09 20 00 58 00 00 32 e0 90 00 } //01 00 
		$a_01_1 = {00 47 65 74 54 79 70 65 } //01 00  䜀瑥祔数
		$a_01_2 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //01 00  䌀敲瑡䥥獮慴据e
		$a_01_3 = {00 53 75 62 73 74 72 69 6e 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}