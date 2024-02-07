
rule Adware_Win32_Kraddare_DK_MTB{
	meta:
		description = "Adware:Win32/Kraddare.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_81_0 = {75 70 64 61 74 65 2e 6d 69 6e 64 74 6f 70 2e 6b 72 } //02 00  update.mindtop.kr
		$a_81_1 = {74 6f 74 61 6c 6c 6f 67 2e 63 6f 2e 6b 72 2f 6c 6f 67 2f } //01 00  totallog.co.kr/log/
		$a_81_2 = {44 4f 57 4e 4c 4f 41 44 20 4c 41 55 4e 43 48 45 52 20 4d 41 4e 41 47 45 52 } //01 00  DOWNLOAD LAUNCHER MANAGER
		$a_81_3 = {43 57 65 62 42 72 6f 77 73 65 72 32 } //01 00  CWebBrowser2
		$a_81_4 = {6c 61 75 6e 63 2e 65 78 65 } //00 00  launc.exe
	condition:
		any of ($a_*)
 
}