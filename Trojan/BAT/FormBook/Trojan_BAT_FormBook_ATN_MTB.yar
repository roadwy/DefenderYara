
rule Trojan_BAT_FormBook_ATN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 44 06 1f 16 5d 13 07 11 04 11 05 28 ?? 00 00 2b 11 06 28 ?? 00 00 2b 28 ?? 00 00 2b 11 07 91 13 08 06 17 58 09 5d 13 09 07 06 91 11 08 61 07 11 09 91 59 20 00 01 00 00 58 13 0a 07 06 11 0a d2 9c 06 17 58 0a 06 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_ATN_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58 } //2
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {48 00 65 00 61 00 6c 00 74 00 68 00 53 00 74 00 6f 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 HealthStopClient
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}