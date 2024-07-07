
rule Trojan_BAT_Taskun_MB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 03 06 0c 08 6f 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 0d 09 74 90 01 03 1b 17 28 90 01 03 06 13 04 11 04 28 90 01 03 06 26 07 0a 2b 00 06 2a 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {67 65 74 5f 57 65 62 42 72 6f 77 73 65 72 } //1 get_WebBrowser
		$a_01_4 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 } //1 Create__Instance
		$a_01_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}