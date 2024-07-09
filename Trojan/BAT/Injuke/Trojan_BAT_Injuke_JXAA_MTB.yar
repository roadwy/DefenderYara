
rule Trojan_BAT_Injuke_JXAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.JXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0a 16 11 0a 8e 69 28 ?? 00 00 06 13 07 } //2
		$a_01_1 = {64 00 73 00 6b 00 66 00 6f 00 69 00 77 00 65 00 68 00 66 00 } //1 dskfoiwehf
		$a_01_2 = {77 00 65 00 77 00 66 00 68 00 68 00 69 00 64 00 73 00 66 00 77 00 65 00 } //1 wewfhhidsfwe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}