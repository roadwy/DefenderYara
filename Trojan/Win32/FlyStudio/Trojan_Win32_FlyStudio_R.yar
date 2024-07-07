
rule Trojan_Win32_FlyStudio_R{
	meta:
		description = "Trojan:Win32/FlyStudio.R,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7c 53 4e 73 73 65 7c 63 3a 5c 77 69 6e 64 6f 77 73 7c } //2 |SNsse|c:\windows|
		$a_01_1 = {4d 5a 4f 30 33 2e 65 78 65 } //1 MZO03.exe
		$a_01_2 = {48 54 54 50 2f 31 2e 31 00 65 70 74 3a 20 } //1 呈偔ㄯㄮ攀瑰›
		$a_01_3 = {69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5f 73 65 72 76 65 72 } //1 internet explorer_server
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}