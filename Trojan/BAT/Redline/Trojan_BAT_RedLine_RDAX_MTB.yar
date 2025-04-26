
rule Trojan_BAT_RedLine_RDAX_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 64 34 39 63 61 38 32 2d 37 32 61 33 2d 34 61 33 33 2d 61 64 30 35 2d 63 39 33 66 32 34 62 39 39 31 38 62 } //1 ed49ca82-72a3-4a33-ad05-c93f24b9918b
		$a_03_1 = {91 61 d2 9c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f 94 00 00 0a 17 59 fe 01 0b 07 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}