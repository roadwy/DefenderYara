
rule Trojan_Win64_AbuseCommBack_X{
	meta:
		description = "Trojan:Win64/AbuseCommBack.X,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 00 70 00 3e 00 44 00 33 00 34 00 30 00 34 00 31 00 34 00 31 00 34 00 35 00 39 00 42 00 43 00 37 00 32 00 30 00 36 00 43 00 43 00 34 00 41 00 46 00 45 00 43 00 31 00 36 00 41 00 33 00 34 00 30 00 33 00 46 00 32 00 36 00 32 00 43 00 30 00 39 00 33 00 37 00 41 00 37 00 33 00 32 00 43 00 31 00 32 00 36 00 34 00 34 00 45 00 37 00 43 00 41 00 39 00 37 00 46 00 30 00 36 00 31 00 35 00 32 00 30 00 31 00 3c 00 2f 00 70 00 3e 00 } //01 00 
		$a_01_1 = {44 33 34 30 34 31 34 31 34 35 39 42 43 37 32 30 36 43 43 34 41 46 45 43 31 36 41 33 34 30 33 46 32 36 32 43 30 39 33 37 41 37 33 32 43 31 32 36 34 34 45 37 43 41 39 37 46 30 36 31 35 32 30 31 00 00 00 00 00 00 00 00 } //01 00 
		$a_01_2 = {74 61 62 6c 65 69 64 44 33 34 30 34 31 34 31 34 35 39 42 43 37 32 30 36 43 43 34 41 46 45 43 31 36 41 33 34 30 33 46 32 36 32 43 30 39 33 37 41 37 33 32 43 31 32 36 34 34 45 37 43 41 39 37 46 30 36 31 35 32 30 31 69 64 } //01 00 
	condition:
		any of ($a_*)
 
}