
rule TrojanDownloader_Win32_Ompiw_A{
	meta:
		description = "TrojanDownloader:Win32/Ompiw.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 46 0c 10 75 3d 56 68 80 05 00 00 8d 4c 24 18 6a 01 51 e8 } //1
		$a_01_1 = {89 59 10 8a 5c 31 04 30 1c 38 8b 59 10 40 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}