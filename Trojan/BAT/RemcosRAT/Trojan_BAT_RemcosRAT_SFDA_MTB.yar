
rule Trojan_BAT_RemcosRAT_SFDA_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SFDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? 00 00 06 16 61 d2 9c 25 17 0f 00 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? 00 00 06 16 60 d2 9c 25 18 0f 00 28 ?? 00 00 0a 20 ff 00 00 00 5f d2 9c 13 0a 1b 13 18 } //2
		$a_03_1 = {04 19 8d 01 00 00 01 25 16 11 04 9c 25 17 11 05 9c 25 18 11 06 9c 6f ?? 00 00 0a 11 11 } //1
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}