
rule Trojan_BAT_Rozena_SBDF_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SBDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 09 8e 69 7e 01 00 00 04 7e 02 00 00 04 28 ?? 00 00 06 13 04 09 16 11 04 6e 28 ?? 00 00 0a 09 8e 69 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}