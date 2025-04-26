
rule Trojan_BAT_njRAT_RDAA_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 13 0d 11 06 28 ?? ?? ?? ?? 16 fe 02 13 0e 11 0e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}