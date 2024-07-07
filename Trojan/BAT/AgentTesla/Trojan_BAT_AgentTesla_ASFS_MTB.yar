
rule Trojan_BAT_AgentTesla_ASFS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 28 90 01 01 01 00 06 5d 28 90 01 01 01 00 06 61 28 90 01 01 01 00 06 d2 07 09 17 58 07 8e 69 5d 91 28 90 01 01 01 00 06 d2 59 20 00 01 00 00 58 28 90 01 01 01 00 06 28 90 01 01 01 00 06 d2 9c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}