
rule TrojanDownloader_Win32_Npbro_A{
	meta:
		description = "TrojanDownloader:Win32/Npbro.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 61 79 48 65 6c 6c 6f 00 } //1
		$a_03_1 = {8b 11 52 a1 ?? ?? ?? ?? 8b 48 70 ff d1 83 c4 08 } //1
		$a_03_2 = {6a 00 6a 00 8d 8d ?? ?? ?? ?? 51 8b 55 ?? 52 6a 00 } //1
		$a_03_3 = {83 c2 01 52 a1 ?? ?? ?? ?? 8b 48 24 ff d1 83 c4 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}