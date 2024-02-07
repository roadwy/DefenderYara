
rule Trojan_Win32_Remdruk_A{
	meta:
		description = "Trojan:Win32/Remdruk.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 56 8b 74 24 14 8a 1c 07 30 1c 31 40 3b c5 72 02 33 c0 41 3b ca 72 ee 5e 5b 5f 5d c3 } //01 00 
		$a_01_1 = {31 64 4d 33 75 75 34 6a 37 46 77 34 73 6a 6e 62 63 77 6c 44 71 65 74 34 46 37 4a 79 75 } //01 00  1dM3uu4j7Fw4sjnbcwlDqet4F7Jyu
		$a_01_2 = {77 69 74 68 20 4d 53 30 35 2d 30 31 30 2b } //00 00  with MS05-010+
	condition:
		any of ($a_*)
 
}