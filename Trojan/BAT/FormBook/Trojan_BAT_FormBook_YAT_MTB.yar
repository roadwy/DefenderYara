
rule Trojan_BAT_FormBook_YAT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.YAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 36 00 00 5d 07 09 20 00 36 00 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 06 07 09 17 58 20 00 36 00 00 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 06 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d a9 } //10
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_4 = {53 00 77 00 69 00 74 00 63 00 68 00 56 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //1 SwitchVsVersion
		$a_01_5 = {31 00 32 00 44 00 59 00 34 00 35 00 46 00 46 00 35 00 34 00 53 00 45 00 59 00 38 00 51 00 4b 00 59 00 47 00 42 00 41 00 35 00 52 00 } //1 12DY45FF54SEY8QKYGBA5R
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}