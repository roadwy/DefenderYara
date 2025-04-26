
rule Trojan_BAT_AgentTesla_MBHB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 07 09 8e 69 5d 09 11 07 09 8e 69 5d 91 11 04 11 07 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 09 11 07 17 58 09 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 00 } //1
		$a_01_1 = {32 00 46 00 34 00 35 00 48 00 38 00 46 00 34 00 46 00 45 00 34 00 45 00 51 00 53 00 35 00 44 00 38 00 35 00 38 00 35 00 54 00 44 00 } //1 2F45H8F4FE4EQS5D8585TD
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}