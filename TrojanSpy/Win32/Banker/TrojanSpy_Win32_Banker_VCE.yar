
rule TrojanSpy_Win32_Banker_VCE{
	meta:
		description = "TrojanSpy:Win32/Banker.VCE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 2e 76 62 73 } //1 \win.vbs
		$a_01_1 = {66 62 50 72 6f 66 69 6c 65 42 72 6f 77 73 65 72 } //1 fbProfileBrowser
		$a_03_2 = {85 c0 76 1e 68 01 00 11 00 6a 1b 68 00 01 00 00 68 ?? ?? ?? ?? 6a 00 e8 } //1
		$a_03_3 = {0f 8e dd 00 00 00 bb 01 00 00 00 8d 45 f4 50 b9 01 00 00 00 8b d3 8b 45 fc e8 ?? ?? ?? ff 8b 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 0f 84 aa 00 00 00 8d 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanSpy_Win32_Banker_VCE_2{
	meta:
		description = "TrojanSpy:Win32/Banker.VCE,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 23 74 75 61 23 6c 69 7a 61 63 23 61 6f 2e 65 23 78 65 } //1 a#tua#lizac#ao.e#xe
		$a_01_1 = {70 23 61 23 73 23 73 23 77 25 64 25 } //1 p#a#s#s#w%d%
		$a_01_2 = {6c 2a 23 6f 67 23 69 6e } //1 l*#og#in
		$a_01_3 = {68 74 23 74 70 3a 2f 2f 6c 6f 23 67 69 6e 2e } //1 ht#tp://lo#gin.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}