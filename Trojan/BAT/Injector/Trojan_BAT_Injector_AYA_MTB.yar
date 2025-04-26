
rule Trojan_BAT_Injector_AYA_MTB{
	meta:
		description = "Trojan:BAT/Injector.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 11 09 08 28 0d 00 00 06 5d 08 11 09 08 28 0d 00 00 06 5d 91 07 11 09 07 28 0d 00 00 06 5d 91 61 08 11 09 17 d6 08 28 0d 00 00 06 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 11 09 17 d6 13 09 11 09 11 08 31 b7 } //2
		$a_01_1 = {48 58 58 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 HXX.Form1.resources
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}