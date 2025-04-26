
rule Trojan_BAT_LokiBot_SPFM_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SPFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 04 59 0a 06 20 00 01 00 00 58 20 ff 00 00 00 5f 0b } //1
		$a_03_1 = {02 07 11 05 91 11 06 61 11 08 28 ?? ?? ?? 06 13 09 11 0f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}