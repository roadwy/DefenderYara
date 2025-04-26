
rule Trojan_BAT_AgentTesla_BAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 5a 11 3d 20 af 06 00 00 95 2e 03 16 2b 01 17 17 59 11 3d 20 22 0e 00 00 95 5f 11 3d 20 d1 0a 00 00 95 61 58 80 08 00 00 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}