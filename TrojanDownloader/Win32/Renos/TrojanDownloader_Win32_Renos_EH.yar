
rule TrojanDownloader_Win32_Renos_EH{
	meta:
		description = "TrojanDownloader:Win32/Renos.EH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 07 bb fe 00 00 00 eb 04 85 db 7e 15 8d 4c 24 0c 51 e8 ?? ?? ff ff 8b 44 24 10 83 c4 04 3b c3 7c eb } //1
		$a_01_1 = {33 d6 81 f2 39 30 00 00 52 68 } //1
		$a_03_2 = {68 10 27 00 00 ?? ?? ?? ?? ?? 6a 0c ?? 68 00 14 2d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}