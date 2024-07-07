
rule Trojan_BAT_PrivateLoader_APL_MTB{
	meta:
		description = "Trojan:BAT/PrivateLoader.APL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 18 18 8c 90 01 01 00 00 01 a2 25 19 18 8d 1f 00 00 01 25 17 18 8d 1f 00 00 01 25 16 11 06 a2 25 17 02 7b 1b 00 00 04 17 8d 1f 00 00 01 25 16 1c 8c 90 01 01 00 00 01 a2 14 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}