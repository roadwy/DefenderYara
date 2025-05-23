
rule Trojan_Win32_Belanit_C{
	meta:
		description = "Trojan:Win32/Belanit.C,SIGNATURE_TYPE_PEHSTR_EXT,19 00 18 00 07 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 48 6f 6f 6b } //1 AppHook
		$a_00_1 = {4d 6f 75 73 65 48 6f 6f 6b } //1 MouseHook
		$a_00_2 = {73 6e 69 66 66 } //1 sniff
		$a_00_3 = {73 69 6c 65 6e 74 } //1 silent
		$a_01_4 = {7e 53 79 73 74 65 6d 43 61 63 68 65 2e 62 61 74 00 00 00 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00 } //1
		$a_00_5 = {33 d2 33 c9 8a 50 02 33 db 8a 48 01 8a 18 89 5d f4 83 c0 03 8b 1c 96 8b 7d f4 03 9c 8e 00 04 00 00 03 9c be 00 08 00 00 8b 7d e8 c1 fb 10 } //10
		$a_02_6 = {8b f0 85 f6 0f 84 90 90 00 00 00 6a 00 68 00 00 00 80 6a 00 6a 00 8b c7 e8 ?? ?? ?? ff 50 56 e8 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*10+(#a_02_6  & 1)*10) >=24
 
}