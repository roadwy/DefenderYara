
rule PWS_Win32_Cimuz_O{
	meta:
		description = "PWS:Win32/Cimuz.O,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {77 65 62 70 6f 73 74 36 34 2e 64 6c 6c } //01 00  webpost64.dll
		$a_01_1 = {48 54 54 50 4d 61 69 6c 20 50 61 73 73 77 6f 72 64 32 } //02 00  HTTPMail Password2
		$a_01_2 = {5f 4b 65 79 4c 6f 67 2e 74 78 74 } //03 00  _KeyLog.txt
		$a_01_3 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 73 74 72 50 68 6f 74 6f 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 5c 33 30 37 34 38 5f 25 73 22 } //02 00  Content-Disposition: form-data; name="strPhoto"; filename="\30748_%s"
		$a_01_4 = {49 45 3a 50 61 73 73 77 6f 72 64 2d 50 72 6f 74 65 63 74 65 64 20 73 69 74 65 73 } //00 00  IE:Password-Protected sites
	condition:
		any of ($a_*)
 
}