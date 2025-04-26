
rule Trojan_Win32_Farfli_F_MTB{
	meta:
		description = "Trojan:Win32/Farfli.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 61 69 64 75 2e 63 6f 6d } //1 baidu.com
		$a_01_1 = {53 62 72 6a 61 72 20 4b 62 73 6b 62 } //1 Sbrjar Kbskb
		$a_01_2 = {48 69 70 70 6f 50 7a 69 } //1 HippoPzi
		$a_01_3 = {4a 62 72 6a 61 2e 65 78 65 } //1 Jbrja.exe
		$a_01_4 = {74 61 74 75 73 62 61 72 2e 62 6d 70 } //1 tatusbar.bmp
		$a_01_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_6 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}