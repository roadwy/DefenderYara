
rule Trojan_BAT_Injuke_LNAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.LNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 07 08 16 6f 90 01 01 00 00 0a 0d 12 03 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 2d 13 08 16 2d 07 17 25 2c 09 58 0c 08 07 6f 90 01 01 00 00 0a 32 c9 90 00 } //4
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}