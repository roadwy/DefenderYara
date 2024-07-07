
rule TrojanDownloader_Win32_Remcos_PI_MTB{
	meta:
		description = "TrojanDownloader:Win32/Remcos.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 db 8b 04 8a 88 c7 88 e3 c1 e8 90 01 01 c1 e3 90 01 01 88 c3 89 1c 8a 49 79 90 00 } //2
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}