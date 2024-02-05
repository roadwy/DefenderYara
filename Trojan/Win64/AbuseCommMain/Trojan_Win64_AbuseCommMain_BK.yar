
rule Trojan_Win64_AbuseCommMain_BK{
	meta:
		description = "Trojan:Win64/AbuseCommMain.BK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 78 00 3a 00 38 00 42 00 37 00 43 00 35 00 43 00 30 00 34 00 42 00 37 00 34 00 33 00 31 00 32 00 30 00 30 00 36 00 34 00 35 00 43 00 39 00 45 00 31 00 39 00 30 00 42 00 42 00 31 00 45 00 46 00 41 00 42 00 42 00 46 00 42 00 33 00 38 00 32 00 36 00 38 00 31 00 30 00 41 00 41 00 46 00 43 00 46 00 46 00 30 00 31 00 41 00 43 00 46 00 39 00 42 00 34 00 30 00 38 00 30 00 45 00 35 00 35 00 30 00 32 00 } //01 00 
		$a_02_1 = {38 42 37 43 35 43 30 34 42 37 34 33 31 32 30 30 36 34 35 43 39 45 31 39 30 42 42 31 45 46 41 42 42 46 42 33 38 32 36 38 31 30 41 41 46 43 46 46 30 31 41 43 46 39 42 34 30 38 30 45 35 35 30 32 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00 90 00 } //01 00 
		$a_02_2 = {38 42 37 43 35 43 30 34 42 37 34 33 31 32 30 30 36 34 35 43 39 45 31 39 30 42 42 31 45 46 41 42 42 46 42 33 38 32 36 38 31 30 41 41 46 43 46 46 30 31 41 43 46 39 42 34 30 38 30 45 35 35 30 32 90 01 0c 4c 00 00 00 90 00 } //01 00 
		$a_00_3 = {5c 74 6f 78 5c 38 42 37 43 35 43 30 34 42 37 34 33 31 32 30 30 36 34 35 43 39 45 31 39 30 42 42 31 45 46 41 42 42 46 42 33 38 32 36 38 31 30 41 41 46 43 46 46 30 31 41 43 46 39 42 34 30 38 30 45 35 35 30 32 2e 68 73 74 72 } //00 00 
	condition:
		any of ($a_*)
 
}