
rule Trojan_Win64_AbuseCommBack_AU{
	meta:
		description = "Trojan:Win64/AbuseCommBack.AU,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 00 70 00 3e 00 45 00 35 00 38 00 44 00 32 00 31 00 35 00 34 00 41 00 37 00 43 00 41 00 41 00 38 00 31 00 37 00 32 00 45 00 38 00 41 00 44 00 31 00 35 00 31 00 35 00 39 00 41 00 46 00 31 00 42 00 31 00 42 00 33 00 33 00 32 00 32 00 45 00 35 00 30 00 41 00 33 00 35 00 44 00 35 00 38 00 32 00 31 00 41 00 32 00 39 00 42 00 43 00 34 00 38 00 44 00 32 00 35 00 31 00 34 00 33 00 44 00 33 00 33 00 46 00 3c 00 2f 00 70 00 3e 00 } //01 00 
		$a_01_1 = {45 35 38 44 32 31 35 34 41 37 43 41 41 38 31 37 32 45 38 41 44 31 35 31 35 39 41 46 31 42 31 42 33 33 32 32 45 35 30 41 33 35 44 35 38 32 31 41 32 39 42 43 34 38 44 32 35 31 34 33 44 33 33 46 00 00 00 00 00 00 00 00 } //01 00 
		$a_01_2 = {74 61 62 6c 65 69 64 45 35 38 44 32 31 35 34 41 37 43 41 41 38 31 37 32 45 38 41 44 31 35 31 35 39 41 46 31 42 31 42 33 33 32 32 45 35 30 41 33 35 44 35 38 32 31 41 32 39 42 43 34 38 44 32 35 31 34 33 44 33 33 46 69 64 } //01 00 
	condition:
		any of ($a_*)
 
}