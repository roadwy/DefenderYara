
rule Trojan_Win32_Ralminey_A{
	meta:
		description = "Trojan:Win32/Ralminey.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 01 51 ff 75 90 01 01 33 c0 c7 45 90 01 01 31 71 32 77 c7 45 90 01 01 33 65 34 72 8d 7d 90 01 01 8d 4d 90 01 01 aa e8 90 00 } //01 00 
		$a_01_1 = {81 fb 94 01 00 00 74 39 81 fb c8 00 00 00 75 31 } //01 00 
		$a_01_2 = {61 41 42 30 41 48 51 41 63 41 41 36 41 43 38 41 4c 77 } //00 00  aAB0AHQAcAA6AC8ALw
	condition:
		any of ($a_*)
 
}