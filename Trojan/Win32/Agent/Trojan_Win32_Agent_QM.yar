
rule Trojan_Win32_Agent_QM{
	meta:
		description = "Trojan:Win32/Agent.QM,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 39 68 75 12 80 79 05 ff 75 0c 80 79 06 15 75 06 80 79 0b e9 74 } //02 00 
		$a_01_1 = {33 41 04 99 f7 fb 8a 06 f6 d0 32 d0 47 } //01 00 
		$a_01_2 = {74 65 73 74 2e 33 33 32 32 2e 6f 72 67 } //01 00 
		$a_01_3 = {5c 31 45 58 50 4c 4f 52 45 2e 45 58 45 } //01 00 
		$a_01_4 = {ce a2 b5 e3 d6 f7 b6 af b7 c0 d3 f9 c8 ed } //00 00 
	condition:
		any of ($a_*)
 
}