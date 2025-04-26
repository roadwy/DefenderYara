
rule Trojan_BAT_Agensla_MBFS_MTB{
	meta:
		description = "Trojan:BAT/Agensla.MBFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 3a 00 3a 00 33 00 3a 00 3a 00 3a 00 30 00 34 00 3a 00 3a 00 3a 00 46 00 46 00 46 00 46 00 3a 00 3a 00 42 00 38 00 3a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}