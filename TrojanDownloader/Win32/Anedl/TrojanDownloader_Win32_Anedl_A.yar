
rule TrojanDownloader_Win32_Anedl_A{
	meta:
		description = "TrojanDownloader:Win32/Anedl.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 76 20 22 6c 6f 61 64 22 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 } //1 /v "load" /t reg_sz /d
		$a_03_1 = {80 7d fb 01 75 ?? 81 fb b8 0b 00 00 76 ?? 6a 01 6a 00 6a 00 } //1
		$a_03_2 = {68 e8 03 00 00 e8 ?? ?? ?? ?? 6a 00 8d 45 ?? e8 ?? ?? ?? ?? ff 75 90 1b 01 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}