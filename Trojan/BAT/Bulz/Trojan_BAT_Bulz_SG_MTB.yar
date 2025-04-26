
rule Trojan_BAT_Bulz_SG_MTB{
	meta:
		description = "Trojan:BAT/Bulz.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 72 21 13 00 70 28 88 00 00 0a 28 7e 00 00 0a 72 72 09 00 70 72 e8 04 00 70 6f 6d 00 00 0a 72 4b 13 00 70 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}