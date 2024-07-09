
rule Trojan_BAT_FormBook_MLGA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MLGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 ?? ?? ?? 06 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8 06 17 58 } //2
		$a_01_1 = {47 00 72 00 65 00 65 00 6e 00 50 00 69 00 78 00 65 00 6c 00 73 00 43 00 61 00 6c 00 63 00 75 00 6c 00 61 00 74 00 6f 00 72 00 } //1 GreenPixelsCalculator
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}