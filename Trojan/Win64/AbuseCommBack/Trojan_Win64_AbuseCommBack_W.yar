
rule Trojan_Win64_AbuseCommBack_W{
	meta:
		description = "Trojan:Win64/AbuseCommBack.W,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 00 70 00 3e 00 38 00 38 00 32 00 34 00 35 00 42 00 42 00 38 00 33 00 46 00 31 00 34 00 46 00 44 00 32 00 45 00 43 00 35 00 31 00 37 00 45 00 33 00 42 00 30 00 39 00 45 00 35 00 36 00 46 00 39 00 36 00 38 00 43 00 31 00 43 00 34 00 43 00 44 00 38 00 31 00 36 00 32 00 44 00 35 00 45 00 35 00 33 00 34 00 41 00 44 00 30 00 39 00 34 00 33 00 38 00 37 00 31 00 32 00 45 00 38 00 44 00 38 00 35 00 44 00 3c 00 2f 00 70 00 3e 00 } //01 00 
		$a_01_1 = {38 38 32 34 35 42 42 38 33 46 31 34 46 44 32 45 43 35 31 37 45 33 42 30 39 45 35 36 46 39 36 38 43 31 43 34 43 44 38 31 36 32 44 35 45 35 33 34 41 44 30 39 34 33 38 37 31 32 45 38 44 38 35 44 00 00 00 00 00 00 00 00 } //01 00 
		$a_01_2 = {74 61 62 6c 65 69 64 38 38 32 34 35 42 42 38 33 46 31 34 46 44 32 45 43 35 31 37 45 33 42 30 39 45 35 36 46 39 36 38 43 31 43 34 43 44 38 31 36 32 44 35 45 35 33 34 41 44 30 39 34 33 38 37 31 32 45 38 44 38 35 44 69 64 } //01 00 
	condition:
		any of ($a_*)
 
}