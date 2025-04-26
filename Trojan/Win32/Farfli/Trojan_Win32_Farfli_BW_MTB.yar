
rule Trojan_Win32_Farfli_BW_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 5c 24 3c 89 5c 24 44 c6 44 24 20 4d c6 44 24 21 6f c6 44 24 22 7a 88 54 24 23 88 4c 24 26 c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30 c6 44 24 2b 20 c6 44 24 2c 28 c6 44 24 2d 63 c6 44 24 2e 6f c6 44 24 2f 6d c6 44 24 30 70 88 4c 24 31 c6 44 24 32 74 88 54 24 33 c6 44 24 34 62 c6 44 24 36 65 c6 44 24 37 29 88 5c 24 38 ff 15 } //2
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 2e 74 78 74 } //1 C:\ProgramData\1.txt
		$a_01_2 = {31 30 33 2e 35 39 2e 31 30 33 2e 31 36 2f 53 48 45 4c 4c 2e 74 78 74 } //1 103.59.103.16/SHELL.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}