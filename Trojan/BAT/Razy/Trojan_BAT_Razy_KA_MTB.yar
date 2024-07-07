
rule Trojan_BAT_Razy_KA_MTB{
	meta:
		description = "Trojan:BAT/Razy.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 59 0d 38 90 01 01 00 00 00 07 09 6f 90 01 01 00 00 0a 74 90 01 01 00 00 1b 13 04 02 11 04 16 94 91 13 05 02 11 04 16 94 02 11 04 17 94 91 9c 02 11 04 17 94 11 05 9c 09 17 59 0d 09 16 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}