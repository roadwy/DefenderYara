
rule Adware_Win32_Gomsek{
	meta:
		description = "Adware:Win32/Gomsek,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 47 4f 4d 53 45 4b 2e 43 4f 4d 5c } //01 00  SOFTWARE\GOMSEK.COM\
		$a_01_1 = {43 44 69 72 65 63 74 4b 65 79 77 6f 72 64 41 70 70 3a 3a 55 70 64 61 74 65 54 68 72 65 61 64 28 29 20 65 72 72 6f 72 } //01 00  CDirectKeywordApp::UpdateThread() error
		$a_01_2 = {25 73 3f 63 6f 6d 70 61 6e 79 49 44 3d 25 73 26 6d 61 63 3d 25 73 26 76 65 72 3d 25 64 26 50 72 6f 67 49 44 3d 25 73 } //00 00  %s?companyID=%s&mac=%s&ver=%d&ProgID=%s
		$a_00_3 = {60 0f } //00 00  འ
	condition:
		any of ($a_*)
 
}