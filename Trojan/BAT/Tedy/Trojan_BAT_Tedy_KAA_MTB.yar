
rule Trojan_BAT_Tedy_KAA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 02 08 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 fe 01 0d 09 2c 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}