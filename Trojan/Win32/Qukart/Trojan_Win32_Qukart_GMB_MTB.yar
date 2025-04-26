
rule Trojan_Win32_Qukart_GMB_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 45 78 49 42 7a 58 6d 5a 34 } //1 AExIBzXmZ4
		$a_01_1 = {75 69 41 6e 6e 50 68 55 } //1 uiAnnPhU
		$a_01_2 = {58 62 51 55 6c 4a 73 56 } //1 XbQUlJsV
		$a_01_3 = {47 6a 59 4a 4c 64 67 68 } //1 GjYJLdgh
		$a_01_4 = {4c 6d 72 4a 6c 64 42 66 } //1 LmrJldBf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}