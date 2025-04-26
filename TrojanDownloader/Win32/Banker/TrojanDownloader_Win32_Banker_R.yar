
rule TrojanDownloader_Win32_Banker_R{
	meta:
		description = "TrojanDownloader:Win32/Banker.R,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 31 55 4e 39 32 36 48 30 31 39 37 39 59 35 36 46 58 44 30 } //1 X1UN926H01979Y56FXD0
		$a_01_1 = {38 32 7a 71 38 35 39 35 48 72 7a 4a 4d 59 30 6c 50 32 30 } //1 82zq8595HrzJMY0lP20
		$a_01_2 = {41 75 74 6f 4d 73 6e 53 65 63 75 72 69 74 79 } //1 AutoMsnSecurity
		$a_01_3 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}