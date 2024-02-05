
rule Trojan_Win64_AbuseCommMain_AN{
	meta:
		description = "Trojan:Win64/AbuseCommMain.AN,SIGNATURE_TYPE_PEHSTR,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 6f 00 78 00 3a 00 37 00 30 00 41 00 36 00 43 00 37 00 36 00 37 00 38 00 33 00 35 00 33 00 31 00 31 00 31 00 38 00 35 00 44 00 42 00 39 00 41 00 35 00 33 00 39 00 37 00 30 00 46 00 45 00 31 00 38 00 44 00 33 00 30 00 41 00 34 00 46 00 38 00 37 00 36 00 42 00 31 00 31 00 45 00 34 00 37 00 30 00 42 00 45 00 39 00 39 00 41 00 34 00 42 00 33 00 39 00 39 00 43 00 37 00 31 00 32 00 33 00 31 00 36 00 42 00 } //01 00 
		$a_01_1 = {37 30 41 36 43 37 36 37 38 33 35 33 31 31 31 38 35 44 42 39 41 35 33 39 37 30 46 45 31 38 44 33 30 41 34 46 38 37 36 42 31 31 45 34 37 30 42 45 39 39 41 34 42 33 39 39 43 37 31 32 33 31 36 42 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00 } //01 00 
		$a_01_2 = {37 30 41 36 43 37 36 37 38 33 35 33 31 31 31 38 35 44 42 39 41 35 33 39 37 30 46 45 31 38 44 33 30 41 34 46 38 37 36 42 31 31 45 34 37 30 42 45 39 39 41 34 42 33 39 39 43 37 31 32 33 31 36 42 90 01 0c 4c 00 00 00 } //01 00 
		$a_01_3 = {5c 74 6f 78 5c 37 30 41 36 43 37 36 37 38 33 35 33 31 31 31 38 35 44 42 39 41 35 33 39 37 30 46 45 31 38 44 33 30 41 34 46 38 37 36 42 31 31 45 34 37 30 42 45 39 39 41 34 42 33 39 39 43 37 31 32 33 31 36 42 2e 68 73 74 72 } //00 00 
	condition:
		any of ($a_*)
 
}