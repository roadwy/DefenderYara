
rule PWS_BAT_HtmStealer_A_MTB{
	meta:
		description = "PWS:BAT/HtmStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {54 6f 6b 65 6e 2d 42 72 6f 77 73 65 72 2d 50 61 73 73 77 6f 72 64 2d 53 74 65 61 6c 65 72 2d 43 72 65 61 74 6f 72 } //01 00  Token-Browser-Password-Stealer-Creator
		$a_81_1 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c 20 22 } //01 00  /C choice /C Y /N /D Y /T 3 & Del "
		$a_81_2 = {73 65 6e 64 68 6f 6f 6b 66 69 6c 65 2e 65 78 65 } //01 00  sendhookfile.exe
		$a_81_3 = {43 3a 2f 74 65 6d 70 2f 57 65 62 42 72 6f 77 73 65 72 50 61 73 73 56 69 65 77 2e 65 78 65 } //00 00  C:/temp/WebBrowserPassView.exe
	condition:
		any of ($a_*)
 
}