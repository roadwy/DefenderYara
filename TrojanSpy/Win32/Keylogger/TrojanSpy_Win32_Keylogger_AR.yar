
rule TrojanSpy_Win32_Keylogger_AR{
	meta:
		description = "TrojanSpy:Win32/Keylogger.AR,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 46 31 7d } //01 00  {F1}
		$a_01_1 = {7b 44 4f 57 4e 7d } //01 00  {DOWN}
		$a_01_2 = {7b 52 49 47 48 54 7d } //01 00  {RIGHT}
		$a_01_3 = {7b 4c 45 46 54 7d } //01 00  {LEFT}
		$a_01_4 = {7b 55 50 7d } //01 00  {UP}
		$a_01_5 = {7b 43 41 50 53 7d } //01 00  {CAPS}
		$a_01_6 = {7b 45 53 43 7d } //01 00  {ESC}
		$a_01_7 = {7b 54 41 42 7d } //05 00  {TAB}
		$a_01_8 = {c6 45 e4 47 c6 45 e5 65 88 5d e6 c6 45 e7 4b c6 45 e8 65 c6 45 e9 79 c6 45 ea 53 88 5d eb c6 45 ec 61 88 5d ed c6 45 ee 65 c6 45 ef 00 } //05 00 
		$a_01_9 = {c6 45 c0 47 c6 45 c1 65 88 5d c2 c6 45 c3 41 c6 45 c4 73 c6 45 c5 79 c6 45 c6 6e c6 45 c7 63 c6 45 c8 4b c6 45 c9 65 c6 45 ca 79 c6 45 cb 53 88 5d cc c6 45 cd 61 88 5d ce c6 45 cf 65 c6 45 d0 00 } //00 00 
	condition:
		any of ($a_*)
 
}