
rule Trojan_Win32_Urelas_AA{
	meta:
		description = "Trojan:Win32/Urelas.AA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 53 4d 50 } //01 00  MSMP
		$a_03_1 = {6a 0f 59 be 90 01 04 f3 a5 66 a5 33 c0 90 00 } //01 00 
		$a_01_2 = {8b f7 81 e6 ff 01 00 00 f7 de 1b f6 89 38 8b c7 f7 de c1 e8 09 03 f0 c1 e6 09 56 } //01 00 
		$a_03_3 = {eb 10 81 7d 90 01 01 50 4b 01 02 74 07 90 00 } //01 00 
		$a_00_4 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } //01 00  golfinfo.ini
		$a_00_5 = {67 00 6f 00 6c 00 66 00 73 00 65 00 74 00 2e 00 69 00 6e 00 69 00 } //00 00  golfset.ini
	condition:
		any of ($a_*)
 
}