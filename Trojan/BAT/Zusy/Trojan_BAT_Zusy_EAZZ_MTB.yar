
rule Trojan_BAT_Zusy_EAZZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EAZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 23 00 00 00 00 00 00 3a 40 07 6f d7 00 00 0a 5a 23 00 00 00 00 00 40 50 40 58 28 d8 00 00 0a 28 d9 00 00 0a 28 da 00 00 0a 0d 12 03 28 db 00 00 0a 28 46 00 00 0a 0a 08 17 58 0c 08 1b 3f bd ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}