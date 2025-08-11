
rule Trojan_BAT_CrimsonRat_AB_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0b 02 02 7b 24 00 00 04 07 16 1b 6f ?? 00 00 0a 7d 1e 00 00 04 07 16 28 ?? 00 00 0a 0c 08 8d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}