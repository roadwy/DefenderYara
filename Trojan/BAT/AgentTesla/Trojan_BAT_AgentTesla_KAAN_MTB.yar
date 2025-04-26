
rule Trojan_BAT_AgentTesla_KAAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 59 11 53 5d 13 5a 11 59 11 54 5d 13 5b 11 51 11 5a 91 13 5c 11 52 11 5b 6f ?? 00 00 0a 13 5d 11 51 11 59 17 58 11 53 5d 91 13 5e 11 5c 11 5d 61 11 5e 59 20 ?? ?? 00 00 58 13 5f 11 51 11 5a 11 5f 20 ?? ?? 00 00 5d d2 9c 00 11 59 17 59 13 59 11 59 16 fe 04 16 fe 01 13 60 11 60 2d a0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}