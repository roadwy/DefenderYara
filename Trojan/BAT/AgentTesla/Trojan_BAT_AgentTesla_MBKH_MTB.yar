
rule Trojan_BAT_AgentTesla_MBKH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 09 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 } //1
		$a_01_1 = {37 00 48 00 4a 00 50 00 38 00 48 00 5a 00 50 00 44 00 55 00 47 00 34 00 38 00 47 00 44 00 33 00 35 00 47 00 59 00 38 00 34 00 35 00 } //1 7HJP8HZPDUG48GD35GY845
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}