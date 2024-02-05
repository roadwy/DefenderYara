
rule Trojan_Win32_Redosdru_X{
	meta:
		description = "Trojan:Win32/Redosdru.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 f3 59 88 1c 11 41 3b c8 } //01 00 
		$a_01_1 = {c6 44 24 0c 4b c6 44 24 0d 6f c6 44 24 0e 74 c6 44 24 0f 68 c6 44 24 10 65 } //01 00 
		$a_01_2 = {c6 45 c9 59 c6 45 cb 54 c6 45 cc 45 c6 45 cd 4d c6 45 ce 5c } //01 00 
		$a_01_3 = {c6 44 24 24 53 c6 44 24 25 4f c6 44 24 26 46 c6 44 24 27 54 } //01 00 
		$a_01_4 = {c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}