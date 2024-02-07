
rule TrojanDownloader_Win32_Garveep_I{
	meta:
		description = "TrojanDownloader:Win32/Garveep.I,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 32 db b8 80 00 00 00 83 f8 10 7f 6a } //05 00 
		$a_01_1 = {99 2b c2 d1 f8 85 c0 0f 8f 45 ff ff ff 88 1c 31 41 3b cf 0f 8c 32 ff ff ff } //02 00 
		$a_00_2 = {72 72 65 63 65 6e 74 2e 70 68 70 } //02 00  rrecent.php
		$a_00_3 = {25 73 5c 73 79 73 5c 2e 2e 5c 25 73 } //02 00  %s\sys\..\%s
		$a_00_4 = {70 72 74 73 68 67 72 64 2e 65 78 65 } //00 00  prtshgrd.exe
	condition:
		any of ($a_*)
 
}