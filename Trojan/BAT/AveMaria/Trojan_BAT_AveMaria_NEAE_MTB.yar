
rule Trojan_BAT_AveMaria_NEAE_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 28 1e 00 00 0a 72 ?? 00 00 70 6f 1f 00 00 0a 6f 20 00 00 0a 0c 06 08 6f 21 00 00 0a 06 18 6f 22 00 00 0a 72 ?? 00 00 70 28 03 00 00 06 0d 06 6f 23 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}