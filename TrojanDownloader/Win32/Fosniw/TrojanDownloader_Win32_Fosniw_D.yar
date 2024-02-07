
rule TrojanDownloader_Win32_Fosniw_D{
	meta:
		description = "TrojanDownloader:Win32/Fosniw.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 44 24 0c 37 90 02 50 c6 44 24 0c 32 90 02 60 c6 44 24 90 01 01 33 90 00 } //01 00 
		$a_01_1 = {49 45 4b 65 79 77 6f 72 64 } //00 00  IEKeyword
	condition:
		any of ($a_*)
 
}