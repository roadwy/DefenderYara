
rule Rogue_Win32_FakeGal{
	meta:
		description = "Rogue:Win32/FakeGal,SIGNATURE_TYPE_PEHSTR,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 57 61 72 6e 69 6e 67 } //01 00  Windows Defender Warning
		$a_01_1 = {73 65 63 75 72 69 74 79 5f 61 6c 65 72 74 } //01 00  security_alert
		$a_01_2 = {41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //01 00  AntiVirusProduct
		$a_01_3 = {62 69 6c 6c 69 6e 67 5f 62 72 6f 77 73 65 72 } //01 00  billing_browser
		$a_01_4 = {70 61 74 68 54 6f 53 69 67 6e 65 64 50 72 6f 64 75 63 74 45 78 65 } //01 00  pathToSignedProductExe
		$a_01_5 = {63 61 6e 27 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 } //00 00  can't connect to SecurityCenter
	condition:
		any of ($a_*)
 
}