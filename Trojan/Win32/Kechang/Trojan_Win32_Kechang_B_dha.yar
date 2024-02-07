
rule Trojan_Win32_Kechang_B_dha{
	meta:
		description = "Trojan:Win32/Kechang.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6b 63 75 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 22 20 2f 76 20 49 45 48 61 72 64 65 6e 49 45 4e 6f 57 61 72 6e } //01 00  hkcu\software\microsoft\Windows\CurrentVersion\Internet Settings" /v IEHardenIENoWarn
		$a_01_1 = {68 6b 63 75 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 50 68 69 73 68 69 6e 67 46 69 6c 74 65 72 22 20 2f 76 20 53 68 6f 77 6e 56 65 72 69 66 79 42 61 6c 6c 6f 6f 6e } //01 00  hkcu\software\microsoft\Internet Explorer\PhishingFilter" /v ShownVerifyBalloon
		$a_01_2 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 64 00 32 00 66 00 6d 00 65 00 2e 00 74 00 6d 00 70 00 } //00 00  \Temp\d2fme.tmp
	condition:
		any of ($a_*)
 
}