
rule Trojan_Win64_AbuseCommMain_EI{
	meta:
		description = "Trojan:Win64/AbuseCommMain.EI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 78 00 3a 00 35 00 39 00 30 00 35 00 32 00 44 00 45 00 38 00 32 00 38 00 38 00 46 00 45 00 30 00 35 00 34 00 35 00 37 00 36 00 46 00 42 00 32 00 44 00 38 00 41 00 44 00 45 00 32 00 37 00 45 00 33 00 35 00 41 00 44 00 39 00 32 00 36 00 39 00 46 00 35 00 41 00 42 00 34 00 42 00 45 00 44 00 39 00 39 00 42 00 44 00 43 00 30 00 31 00 39 00 42 00 38 00 31 00 44 00 34 00 30 00 42 00 39 00 37 00 43 00 } //01 00  tox:59052DE8288FE054576FB2D8ADE27E35AD9269F5AB4BED99BDC019B81D40B97C
		$a_02_1 = {35 39 30 35 32 44 45 38 32 38 38 46 45 30 35 34 35 37 36 46 42 32 44 38 41 44 45 32 37 45 33 35 41 44 39 32 36 39 46 35 41 42 34 42 45 44 39 39 42 44 43 30 31 39 42 38 31 44 34 30 42 39 37 43 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00 90 00 } //01 00 
		$a_02_2 = {35 39 30 35 32 44 45 38 32 38 38 46 45 30 35 34 35 37 36 46 42 32 44 38 41 44 45 32 37 45 33 35 41 44 39 32 36 39 46 35 41 42 34 42 45 44 39 39 42 44 43 30 31 39 42 38 31 44 34 30 42 39 37 43 90 01 0c 4c 00 00 00 90 00 } //01 00 
		$a_00_3 = {5c 74 6f 78 5c 35 39 30 35 32 44 45 38 32 38 38 46 45 30 35 34 35 37 36 46 42 32 44 38 41 44 45 32 37 45 33 35 41 44 39 32 36 39 46 35 41 42 34 42 45 44 39 39 42 44 43 30 31 39 42 38 31 44 34 30 42 39 37 43 2e 68 73 74 72 } //00 00  \tox\59052DE8288FE054576FB2D8ADE27E35AD9269F5AB4BED99BDC019B81D40B97C.hstr
	condition:
		any of ($a_*)
 
}