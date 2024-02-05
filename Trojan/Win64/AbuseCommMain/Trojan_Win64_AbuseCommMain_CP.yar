
rule Trojan_Win64_AbuseCommMain_CP{
	meta:
		description = "Trojan:Win64/AbuseCommMain.CP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 78 00 3a 00 42 00 30 00 32 00 38 00 33 00 38 00 46 00 44 00 34 00 46 00 46 00 38 00 32 00 33 00 36 00 36 00 35 00 46 00 38 00 35 00 35 00 46 00 46 00 37 00 31 00 33 00 36 00 35 00 39 00 42 00 38 00 37 00 31 00 38 00 36 00 42 00 39 00 41 00 44 00 39 00 30 00 43 00 34 00 30 00 46 00 31 00 34 00 38 00 39 00 37 00 37 00 44 00 43 00 35 00 31 00 33 00 35 00 32 00 42 00 44 00 42 00 34 00 33 00 42 00 } //01 00 
		$a_02_1 = {42 30 32 38 33 38 46 44 34 46 46 38 32 33 36 36 35 46 38 35 35 46 46 37 31 33 36 35 39 42 38 37 31 38 36 42 39 41 44 39 30 43 34 30 46 31 34 38 39 37 37 44 43 35 31 33 35 32 42 44 42 34 33 42 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00 90 00 } //01 00 
		$a_02_2 = {42 30 32 38 33 38 46 44 34 46 46 38 32 33 36 36 35 46 38 35 35 46 46 37 31 33 36 35 39 42 38 37 31 38 36 42 39 41 44 39 30 43 34 30 46 31 34 38 39 37 37 44 43 35 31 33 35 32 42 44 42 34 33 42 90 01 0c 4c 00 00 00 90 00 } //01 00 
		$a_00_3 = {5c 74 6f 78 5c 42 30 32 38 33 38 46 44 34 46 46 38 32 33 36 36 35 46 38 35 35 46 46 37 31 33 36 35 39 42 38 37 31 38 36 42 39 41 44 39 30 43 34 30 46 31 34 38 39 37 37 44 43 35 31 33 35 32 42 44 42 34 33 42 2e 68 73 74 72 } //00 00 
	condition:
		any of ($a_*)
 
}