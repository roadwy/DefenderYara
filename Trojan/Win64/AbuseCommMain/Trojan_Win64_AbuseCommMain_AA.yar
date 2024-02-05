
rule Trojan_Win64_AbuseCommMain_AA{
	meta:
		description = "Trojan:Win64/AbuseCommMain.AA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 78 00 3a 00 30 00 30 00 37 00 41 00 32 00 31 00 41 00 32 00 37 00 43 00 33 00 39 00 43 00 43 00 36 00 34 00 44 00 39 00 41 00 42 00 30 00 36 00 36 00 41 00 39 00 41 00 37 00 31 00 42 00 37 00 42 00 30 00 42 00 45 00 35 00 37 00 35 00 45 00 45 00 39 00 44 00 32 00 38 00 37 00 31 00 38 00 39 00 32 00 33 00 35 00 42 00 42 00 31 00 46 00 33 00 37 00 36 00 34 00 33 00 38 00 31 00 35 00 30 00 42 00 } //01 00 
		$a_02_1 = {30 30 37 41 32 31 41 32 37 43 33 39 43 43 36 34 44 39 41 42 30 36 36 41 39 41 37 31 42 37 42 30 42 45 35 37 35 45 45 39 44 32 38 37 31 38 39 32 33 35 42 42 31 46 33 37 36 34 33 38 31 35 30 42 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00 90 00 } //01 00 
		$a_02_2 = {30 30 37 41 32 31 41 32 37 43 33 39 43 43 36 34 44 39 41 42 30 36 36 41 39 41 37 31 42 37 42 30 42 45 35 37 35 45 45 39 44 32 38 37 31 38 39 32 33 35 42 42 31 46 33 37 36 34 33 38 31 35 30 42 90 01 0c 4c 00 00 00 90 00 } //01 00 
		$a_00_3 = {5c 74 6f 78 5c 30 30 37 41 32 31 41 32 37 43 33 39 43 43 36 34 44 39 41 42 30 36 36 41 39 41 37 31 42 37 42 30 42 45 35 37 35 45 45 39 44 32 38 37 31 38 39 32 33 35 42 42 31 46 33 37 36 34 33 38 31 35 30 42 2e 68 73 74 72 } //00 00 
	condition:
		any of ($a_*)
 
}