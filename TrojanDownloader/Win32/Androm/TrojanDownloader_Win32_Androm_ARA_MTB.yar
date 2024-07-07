
rule TrojanDownloader_Win32_Androm_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Androm.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 34 30 01 40 3b c2 72 f7 } //4
		$a_80_1 = {53 68 65 6c 6c 63 6f 64 65 20 44 6f 77 6e 6c 6f 61 64 65 72 } //Shellcode Downloader  2
	condition:
		((#a_01_0  & 1)*4+(#a_80_1  & 1)*2) >=6
 
}