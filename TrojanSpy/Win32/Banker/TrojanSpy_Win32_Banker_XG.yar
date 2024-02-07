
rule TrojanSpy_Win32_Banker_XG{
	meta:
		description = "TrojanSpy:Win32/Banker.XG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 8b 4d 08 81 f1 90 01 02 00 00 3b c1 75 08 90 09 05 00 e8 90 00 } //01 00 
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //01 00  SELECT * FROM AntiVirusProduct
		$a_01_2 = {52 00 4f 00 4f 00 54 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 32 00 } //02 00  ROOT\SecurityCenter2
		$a_01_3 = {69 6e 6a 65 63 74 5f 73 65 74 74 69 6e 67 } //02 00  inject_setting
		$a_01_4 = {69 6e 6a 65 63 74 5f 61 66 74 65 72 5f 6b 65 79 77 6f 72 64 } //02 00  inject_after_keyword
		$a_01_5 = {69 6e 6a 65 63 74 5f 62 65 66 6f 72 65 5f 6b 65 79 77 6f 72 64 } //01 00  inject_before_keyword
		$a_01_6 = {62 63 30 30 35 39 35 34 34 30 65 38 30 31 66 38 61 35 64 32 61 32 61 64 31 33 62 39 37 39 31 62 } //00 00  bc00595440e801f8a5d2a2ad13b9791b
		$a_00_7 = {5d 04 00 00 e9 5e } //02 80 
	condition:
		any of ($a_*)
 
}