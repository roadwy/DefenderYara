
rule Trojan_BAT_AgentTesla_MBFM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee 07 13 04 dd 03 00 } //01 00 
		$a_01_1 = {33 00 36 00 2e 00 31 00 30 00 34 00 2f 00 75 00 6c 00 74 00 72 00 6f 00 6e 00 2f 00 55 00 76 00 69 } //01 00 
		$a_01_2 = {49 7a 79 6a 79 69 74 66 68 00 4b 66 65 6f } //00 00  穉橹楹晴h晋潥
	condition:
		any of ($a_*)
 
}