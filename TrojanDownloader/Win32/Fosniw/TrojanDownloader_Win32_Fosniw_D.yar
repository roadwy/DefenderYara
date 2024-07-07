
rule TrojanDownloader_Win32_Fosniw_D{
	meta:
		description = "TrojanDownloader:Win32/Fosniw.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 44 24 0c 37 90 02 50 c6 44 24 0c 32 90 02 60 c6 44 24 90 01 01 33 90 00 } //1
		$a_01_1 = {49 45 4b 65 79 77 6f 72 64 } //1 IEKeyword
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}