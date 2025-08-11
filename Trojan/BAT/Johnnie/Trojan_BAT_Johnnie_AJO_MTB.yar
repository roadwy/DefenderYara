
rule Trojan_BAT_Johnnie_AJO_MTB{
	meta:
		description = "Trojan:BAT/Johnnie.AJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 da 0c 0b 2b 30 03 07 91 20 ff 00 00 00 fe 01 16 fe 01 13 05 11 05 2c 12 03 0d 09 07 13 04 11 04 09 11 04 91 17 d6 b4 9c 2b 05 00 03 07 16 9c 00 00 07 17 d6 0b 07 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}