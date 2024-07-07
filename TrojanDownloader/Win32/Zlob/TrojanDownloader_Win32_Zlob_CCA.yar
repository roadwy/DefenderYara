
rule TrojanDownloader_Win32_Zlob_CCA{
	meta:
		description = "TrojanDownloader:Win32/Zlob.CCA,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {ba 7f 96 98 00 eb 0a 46 56 83 c6 10 58 48 8b f0 4a 0b d2 75 f2 } //10
		$a_01_1 = {6c 6f 61 64 00 77 69 6e 64 6f 77 73 00 } //1
		$a_01_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}