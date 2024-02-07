
rule TrojanDownloader_Win32_Lemmy_U{
	meta:
		description = "TrojanDownloader:Win32/Lemmy.U,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {05 53 73 6f 72 65 2e 65 78 65 00 } //01 00 
		$a_01_1 = {56 61 6c 75 65 28 6a 69 6d 6d 79 68 65 6c 70 } //01 00  Value(jimmyhelp
		$a_01_2 = {6d 6f 42 72 6f 77 73 65 72 5f 42 65 66 6f 72 65 4e 61 76 69 67 61 74 65 } //01 00  moBrowser_BeforeNavigate
		$a_01_3 = {73 65 6e 64 65 6d 61 69 6c 74 6f 72 65 67 } //00 00  sendemailtoreg
	condition:
		any of ($a_*)
 
}