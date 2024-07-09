
rule Trojan_BAT_FormBook_ATN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58 } //2
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {48 00 65 00 61 00 6c 00 74 00 68 00 53 00 74 00 6f 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 HealthStopClient
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}