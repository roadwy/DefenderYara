
rule Trojan_Win32_Agent_QP{
	meta:
		description = "Trojan:Win32/Agent.QP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 54 1a ff 80 f2 58 88 54 18 ff 43 4e 75 e1 } //01 00 
		$a_03_1 = {85 c0 0f 84 90 01 02 00 00 c7 05 90 01 04 07 00 01 00 90 00 } //01 00 
		$a_01_2 = {b8 47 65 74 50 39 06 75 f1 b8 72 6f 63 41 39 46 04 } //01 00 
		$a_01_3 = {75 f7 ff 02 48 75 f4 8b 02 59 5d c3 } //01 00 
		$a_00_4 = {72 61 76 6d 6f 6e 64 2e 65 78 65 } //00 00  ravmond.exe
	condition:
		any of ($a_*)
 
}