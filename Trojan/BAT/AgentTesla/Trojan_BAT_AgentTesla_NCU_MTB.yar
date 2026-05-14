
rule Trojan_BAT_AgentTesla_NCU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0b 11 09 18 62 11 09 1c 63 60 d2 13 09 11 09 18 63 11 09 1c 62 60 d2 13 09 11 0a 66 d2 13 0a 11 0a 66 d2 13 0a 11 0b 1f 77 58 20 ff 00 00 00 5f d2 13 0b 11 0b 1f 77 59 20 ff 00 00 00 5f d2 13 0b 11 04 11 09 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}