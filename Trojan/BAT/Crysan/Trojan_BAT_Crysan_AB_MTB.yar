
rule Trojan_BAT_Crysan_AB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 20 00 04 00 00 8d 46 00 00 01 0c 38 09 00 00 00 07 08 16 09 6f 69 00 00 0a 06 08 16 08 8e 69 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}