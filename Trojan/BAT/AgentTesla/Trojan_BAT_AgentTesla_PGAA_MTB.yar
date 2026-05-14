
rule Trojan_BAT_AgentTesla_PGAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 7e 4f 00 00 04 25 3a 17 00 00 00 26 7e 3d 00 00 04 fe 06 7f 00 00 06 73 69 00 00 0a 25 80 4f 00 00 04 02 03 04 6f ?? 00 00 0a 7d 57 00 00 04 16 19 28 6b 00 00 0a 7e 50 00 00 04 25 3a 17 00 00 00 26 7e 3d 00 00 04 fe 06 80 00 00 06 73 6c 00 00 0a 25 80 50 00 00 04 28 07 00 00 2b 7e 51 00 00 04 25 3a 17 00 00 00 26 7e 3d 00 00 04 fe 06 81 00 00 06 73 6e 00 00 0a 25 80 51 00 00 04 28 08 00 00 2b 7e 52 00 00 04 25 3a 17 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}