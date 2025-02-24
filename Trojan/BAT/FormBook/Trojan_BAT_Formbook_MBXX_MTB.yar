
rule Trojan_BAT_Formbook_MBXX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? ?? ?? ?? 0c 04 03 6f ?? ?? ?? ?? 59 0d 03 08 09 } //4
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //3 System.Reflection.Assembly
		$a_01_2 = {4c 00 6f 00 61 00 64 } //2
		$a_01_3 = {47 65 74 50 69 78 65 6c 43 6f 6c 6f 72 } //1 GetPixelColor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}