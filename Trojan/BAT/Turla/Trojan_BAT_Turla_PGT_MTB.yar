
rule Trojan_BAT_Turla_PGT_MTB{
	meta:
		description = "Trojan:BAT/Turla.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 00 67 00 39 00 55 00 63 00 6d 00 46 00 75 00 63 00 33 00 42 00 76 00 63 00 6e 00 51 00 75 00 63 00 48 00 4a 00 76 00 64 00 47 00 38 00 53 00 44 00 30 00 31 00 76 00 5a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}