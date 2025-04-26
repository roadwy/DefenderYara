
rule TrojanDownloader_Win32_Inlev_A{
	meta:
		description = "TrojanDownloader:Win32/Inlev.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 06 48 54 54 50 c7 46 04 31 2e 38 20 c7 46 08 47 45 54 00 66 } //1
		$a_03_1 = {6a 01 ff 75 ?? ff 55 ?? (3b c6|83 f8 ff) 75 06 ff 75 ?? ff 55 ?? 6a 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}