
rule TrojanDownloader_Win32_Webpwnd_A{
	meta:
		description = "TrojanDownloader:Win32/Webpwnd.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 6f 6e 00 00 68 75 72 6c 6d 54 ff 16 } //01 00 
		$a_02_1 = {33 c0 40 80 3c 03 00 75 f9 c7 04 03 5c 90 01 01 2e 65 c7 44 03 04 78 65 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}