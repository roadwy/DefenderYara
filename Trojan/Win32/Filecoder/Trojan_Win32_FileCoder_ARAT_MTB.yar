
rule Trojan_Win32_FileCoder_ARAT_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 65 72 76 69 63 65 40 67 6f 6f 64 6c 75 63 6b 64 61 79 2e 78 79 7a } //service@goodluckday.xyz  2
		$a_80_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6d 73 61 63 63 65 73 73 2e 65 78 65 } //taskkill /f /im msaccess.exe  2
		$a_80_2 = {62 74 63 20 74 6f 20 6d 79 20 61 64 64 72 65 73 73 3a } //btc to my address:  2
		$a_03_3 = {0d 12 03 28 ?? ?? ?? 0a 0c 08 16 06 1f 10 07 5a 08 8e 69 28 ?? ?? ?? 0a 07 17 58 0b 07 02 32 db } //2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_03_3  & 1)*2) >=8
 
}