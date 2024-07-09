
rule TrojanDownloader_Win32_URLDistract_A{
	meta:
		description = "TrojanDownloader:Win32/URLDistract.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {38 00 37 00 31 00 30 00 35 00 31 00 31 00 30 00 31 00 30 00 30 00 31 00 31 00 31 00 31 00 31 00 39 00 31 00 31 00 35 00 33 00 32 00 37 00 38 00 38 00 34 00 } //1 87105110100111119115327884
		$a_00_1 = {44 00 69 00 63 00 69 00 6f 00 6e 00 61 00 72 00 69 00 6f 00 2e 00 76 00 62 00 70 00 } //1 Dicionario.vbp
		$a_03_2 = {0f bf 55 cc 0f bf 45 d4 8b 4d d8 33 d0 51 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c4 ff d6 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d8 ff d6 8d 4d c4 ff d3 b8 02 00 00 00 66 03 c7 70 73 8b f8 e9 f2 fe ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}