
rule TrojanDownloader_Win32_Zlob_ZXJ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZXJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 67 bd 72 fc c9 84 70 56 57 9d da 8d 28 01 ab c4 8e 23 b4 70 00 00 00 80 bf 33 29 36 7b d2 11 b2 0e 00 c0 4f 98 3e 60 } //00 00 
	condition:
		any of ($a_*)
 
}