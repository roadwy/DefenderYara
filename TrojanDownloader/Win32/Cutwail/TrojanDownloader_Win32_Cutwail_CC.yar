
rule TrojanDownloader_Win32_Cutwail_CC{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.CC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 07 c3 55 8b ec 83 c4 fc 8b 75 08 03 76 3c 6a 40 18 ec 77 db db 30 14 ff 76 50 02 34 90 01 01 bd 12 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}