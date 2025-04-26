
rule Trojan_BAT_FormBook_EVO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 06 07 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_EVO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.EVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 0b 02 } //1
		$a_01_1 = {00 53 41 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 00 } //1 匀十卓卓卓卓卓卓卓卓卓卓S
		$a_01_2 = {00 54 48 41 49 30 30 00 } //1 吀䅈ぉ0
		$a_01_3 = {00 54 48 41 49 30 32 00 } //1 吀䅈ぉ2
		$a_01_4 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1 开彟彟彟彟彟_
		$a_01_5 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //1 䌀敲瑡䥥獮慴据e
		$a_01_6 = {00 47 65 74 54 79 70 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}