
rule TrojanDownloader_Win32_Retefe_C{
	meta:
		description = "TrojanDownloader:Win32/Retefe.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 64 24 00 8a 90 01 05 30 90 01 05 83 90 01 01 01 75 ef 90 00 } //1
		$a_01_1 = {99 b9 15 00 00 00 f7 f9 83 c2 0a 0f b7 c2 69 c0 e8 03 00 00 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}