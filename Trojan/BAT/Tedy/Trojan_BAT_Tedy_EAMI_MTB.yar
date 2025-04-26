
rule Trojan_BAT_Tedy_EAMI_MTB{
	meta:
		description = "Trojan:BAT/Tedy.EAMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 9a 28 14 00 00 06 26 06 07 9a 28 15 00 00 06 06 07 9a 72 37 0b 00 70 28 57 00 00 0a 2c 08 06 07 9a 28 16 00 00 06 07 17 58 0b 07 06 8e 69 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}