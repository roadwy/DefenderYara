
rule Trojan_BAT_AgentTesla_NDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 61 6c 6b 66 73 6b 67 64 66 67 64 66 67 64 66 67 64 66 67 73 66 6b 6b 6b 73 78 76 63 78 66 67 66 66 6b 6b 75 69 68 69 6f 64 73 64 67 61 67 2e 64 6c 6c 23 } //01 00  #falkfskgdfgdfgdfgdfgsfkkksxvcxfgffkkuihiodsdgag.dll#
		$a_01_1 = {23 66 73 64 73 66 64 64 66 67 64 66 67 64 73 66 66 73 64 78 76 66 73 6b 61 68 66 68 66 61 6e 6b 6b 6b 61 73 66 23 } //01 00  #fsdsfddfgdfgdsffsdxvfskahfhfankkkasf#
		$a_01_2 = {23 66 61 66 64 61 73 67 73 66 66 67 64 66 67 64 66 73 64 66 64 6b 67 63 66 69 6f 69 6f 61 61 61 61 61 6f 61 61 61 64 73 73 73 61 66 2e 64 6c 6c 23 } //01 00  #fafdasgsffgdfgdfsdfdkgcfioioaaaaaoaaadsssaf.dll#
		$a_01_3 = {67 6f 69 6f 78 67 66 64 67 76 66 73 64 66 66 73 66 73 66 61 64 6b 67 67 66 6b 73 64 73 73 67 62 73 76 } //01 00  goioxgfdgvfsdffsfsfadkggfksdssgbsv
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}