
rule TrojanDownloader_Win32_Upatre_BL{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 04 00 00 00 6a 04 68 00 10 00 00 68 00 00 aa 00 51 ff 93 28 11 00 00 } //1
		$a_01_1 = {b9 80 84 1e 00 89 45 00 03 c1 81 c1 e0 06 5a 00 89 45 fc 03 c1 } //1
		$a_01_2 = {b0 54 fe c8 66 ab b0 44 fe c0 66 ab b0 52 66 ab } //1
		$a_01_3 = {b0 54 48 66 ab b0 50 66 ab 58 04 30 66 ab } //1
		$a_01_4 = {ad ab 8b c2 66 ad 66 ab 8b c2 ac 66 ab 49 75 f0 } //1
		$a_01_5 = {b0 31 66 ab b0 2f 66 ab 8a c1 04 30 66 ab b0 2f 66 ab } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Upatre_BL_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BL,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 10 00 00 68 f8 ff a7 00 6a 00 ff 55 40 } //2
		$a_01_1 = {05 80 84 1e 00 89 45 b8 05 80 8d 5b 00 89 45 f4 5a 03 c2 } //2
		$a_01_2 = {b8 52 00 45 00 40 ab b0 52 66 ab } //2
		$a_01_3 = {b8 54 00 45 00 48 ab b0 52 66 ab } //2
		$a_01_4 = {b0 2e 48 66 ab b0 53 6a 50 66 ab 58 66 ab 58 48 66 ab } //2
		$a_01_5 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //1
		$a_01_6 = {00 74 65 78 74 2f 2a 00 } //1 琀硥⽴*
		$a_01_7 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}