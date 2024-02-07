
rule Trojan_Win32_Wysotot_A{
	meta:
		description = "Trojan:Win32/Wysotot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 00 70 00 2e 00 73 00 6f 00 66 00 74 00 33 00 36 00 35 00 2e 00 63 00 6f 00 6d 00 2f 00 47 00 64 00 70 00 2f 00 66 00 69 00 6e 00 69 00 73 00 68 00 } //01 00  up.soft365.com/Gdp/finish
		$a_01_1 = {42 00 65 00 67 00 69 00 6e 00 20 00 53 00 74 00 61 00 72 00 74 00 20 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 4d 00 6f 00 6e 00 } //01 00  Begin Start ShortcutMon
		$a_01_2 = {2e 3f 41 56 43 65 47 64 70 53 76 63 53 68 6f 72 74 63 75 74 4d 6f 6e 40 } //01 00  .?AVCeGdpSvcShortcutMon@
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 65 00 53 00 61 00 66 00 65 00 53 00 65 00 63 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //00 00  SOFTWARE\eSafeSecControl
		$a_00_4 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}