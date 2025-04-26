
rule Trojan_BAT_Crysan_YFX_MTB{
	meta:
		description = "Trojan:BAT/Crysan.YFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 04 02 11 04 91 06 61 07 09 91 61 d2 9c 07 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}