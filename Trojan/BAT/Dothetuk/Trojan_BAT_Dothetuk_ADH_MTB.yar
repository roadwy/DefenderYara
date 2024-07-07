
rule Trojan_BAT_Dothetuk_ADH_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.ADH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0e 2b 30 00 00 08 11 0c 11 0e 8f 14 00 00 02 7c 2c 00 00 04 7b 22 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 00 00 de 05 26 00 00 de 00 00 11 0e 17 58 13 0e 11 0e 6a 11 07 6e fe 04 13 0f 11 0f 2d c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Dothetuk_ADH_MTB_2{
	meta:
		description = "Trojan:BAT/Dothetuk.ADH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 03 07 05 0e 04 73 09 00 00 0a 0d 09 0e 06 1e 5b 6f 90 01 03 0a 13 04 28 90 01 03 0a 13 05 11 05 17 6f 90 01 03 0a 08 8e 69 8d 0a 00 00 01 13 06 16 13 07 11 05 11 04 06 6f 90 01 03 0a 13 08 08 90 00 } //2
		$a_01_1 = {42 00 69 00 74 00 43 00 6f 00 72 00 65 00 4d 00 69 00 72 00 61 00 63 00 6c 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 BitCoreMiracles.exe
		$a_01_2 = {42 00 75 00 6d 00 47 00 43 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 41 00 50 00 50 00 } //1 BumGConsoleAPP
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}