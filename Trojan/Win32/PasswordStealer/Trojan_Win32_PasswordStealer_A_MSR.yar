
rule Trojan_Win32_PasswordStealer_A_MSR{
	meta:
		description = "Trojan:Win32/PasswordStealer.A!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 70 2e 74 78 74 } //01 00  ip.txt
		$a_01_1 = {53 79 73 74 65 6d 2e 74 78 74 } //01 00  System.txt
		$a_01_2 = {50 61 73 73 77 6f 72 64 73 4c 69 73 74 2e 74 78 74 } //01 00  PasswordsList.txt
		$a_01_3 = {42 72 6f 77 73 65 72 73 5c 43 6f 6f 6b 69 65 73 } //01 00  Browsers\Cookies
		$a_01_4 = {42 72 6f 77 73 65 72 73 5c 48 69 73 74 6f 72 79 } //01 00  Browsers\History
		$a_01_5 = {6d 6f 7a 5f 68 69 73 74 6f 72 79 76 69 73 69 74 73 2e 76 69 73 69 74 5f 64 61 74 65 } //01 00  moz_historyvisits.visit_date
		$a_01_6 = {5c 70 6c 61 63 65 73 2e 73 71 6c 69 74 65 } //00 00  \places.sqlite
		$a_01_7 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}