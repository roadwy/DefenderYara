
rule Trojan_BAT_AgentTesla_KABC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 0a d2 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 0a d2 59 20 00 ?? 00 00 58 20 00 ?? 00 00 5d 28 ?? 00 00 0a d2 9c 00 11 07 17 6a 58 13 07 11 07 07 8e 69 17 59 09 17 58 5a 6a fe 02 16 fe 01 13 08 11 08 2d 95 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}