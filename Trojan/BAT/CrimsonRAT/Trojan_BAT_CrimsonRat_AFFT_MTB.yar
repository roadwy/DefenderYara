
rule Trojan_BAT_CrimsonRat_AFFT_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.AFFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 05 28 ?? ?? ?? 06 0b 07 2c 04 17 0c 2b 14 00 06 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}