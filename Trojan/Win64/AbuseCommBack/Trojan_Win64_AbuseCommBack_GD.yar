
rule Trojan_Win64_AbuseCommBack_GD{
	meta:
		description = "Trojan:Win64/AbuseCommBack.GD,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 00 70 00 3e 00 39 00 36 00 30 00 44 00 39 00 38 00 31 00 34 00 45 00 46 00 42 00 46 00 43 00 38 00 39 00 38 00 32 00 33 00 32 00 31 00 39 00 45 00 43 00 43 00 44 00 33 00 31 00 42 00 31 00 37 00 33 00 42 00 31 00 43 00 42 00 39 00 39 00 37 00 35 00 45 00 31 00 38 00 31 00 46 00 46 00 44 00 32 00 41 00 46 00 35 00 33 00 39 00 45 00 30 00 39 00 41 00 32 00 43 00 44 00 45 00 37 00 45 00 36 00 35 00 3c 00 2f 00 70 00 3e 00 } //1 <p>960D9814EFBFC89823219ECCD31B173B1CB9975E181FFD2AF539E09A2CDE7E65</p>
		$a_01_1 = {39 36 30 44 39 38 31 34 45 46 42 46 43 38 39 38 32 33 32 31 39 45 43 43 44 33 31 42 31 37 33 42 31 43 42 39 39 37 35 45 31 38 31 46 46 44 32 41 46 35 33 39 45 30 39 41 32 43 44 45 37 45 36 35 00 00 00 00 00 00 00 00 } //1
		$a_01_2 = {74 61 62 6c 65 69 64 39 36 30 44 39 38 31 34 45 46 42 46 43 38 39 38 32 33 32 31 39 45 43 43 44 33 31 42 31 37 33 42 31 43 42 39 39 37 35 45 31 38 31 46 46 44 32 41 46 35 33 39 45 30 39 41 32 43 44 45 37 45 36 35 69 64 } //1 tableid960D9814EFBFC89823219ECCD31B173B1CB9975E181FFD2AF539E09A2CDE7E65id
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}