
rule Trojan_BAT_AgentTesla_EAAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 09 11 06 58 1f 64 5d 13 07 09 11 06 5a 1f 64 5d 13 08 09 11 06 61 1f 64 5d 13 09 02 09 11 06 6f f7 00 00 0a 13 0a 04 03 6f f8 00 00 0a 59 13 0b 11 0a 11 0b 03 28 65 00 00 06 00 00 11 06 17 58 13 06 11 06 02 6f f9 00 00 0a 2f 0b 03 6f f8 00 00 0a 04 fe 04 2b 01 16 13 0c 11 0c 2d a1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}