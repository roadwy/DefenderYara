
rule VirTool_Win32_Injector_HP{
	meta:
		description = "VirTool:Win32/Injector.HP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 58 ff d3 68 90 01 04 e8 90 00 } //01 00 
		$a_01_1 = {51 8b ce ff 37 8b 01 33 04 24 aa 58 59 46 8b c3 48 74 09 8b d8 e2 e9 } //01 00 
		$a_01_2 = {5b 2b f3 8b c3 50 eb ef } //01 00 
		$a_03_3 = {8b d8 58 5a 51 50 52 68 90 01 04 ff d3 a1 90 01 04 b9 80 00 00 00 bf 90 00 } //01 00 
		$a_01_4 = {5b 8b 7d fc 8b 73 18 8b 43 1c 8b 4b 0c 8b 53 08 ff d2 8b 4b 20 8b 45 fc 03 45 f4 51 ff d0 } //01 00 
		$a_01_5 = {eb d3 47 d9 18 e6 e6 90 90 ee 70 8a 58 b0 d4 99 4c 0b 1a b2 fd 87 f1 17 ab 28 95 65 52 6e 33 3b } //01 00 
		$a_00_6 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}