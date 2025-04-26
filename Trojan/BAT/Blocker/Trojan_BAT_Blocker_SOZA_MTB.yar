
rule Trojan_BAT_Blocker_SOZA_MTB{
	meta:
		description = "Trojan:BAT/Blocker.SOZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 6f ?? 00 00 0a 06 6f ?? 00 00 0a 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d de 17 08 2c 06 08 6f ?? 00 00 0a dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}