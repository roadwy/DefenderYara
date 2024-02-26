
rule Ransom_Win64_Megazord_SA_MTB{
	meta:
		description = "Ransom:Win64/Megazord.SA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 72 65 6c 65 61 73 65 5c 64 65 70 73 5c 6d 65 67 61 7a 6f 72 64 2e 70 64 62 } //01 00  \release\deps\megazord.pdb
		$a_01_1 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //01 00  SystemFunction036
		$a_01_2 = {42 43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //01 00  BCryptGenRandom
		$a_01_3 = {5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 43 3a 5c 24 52 45 43 59 43 4c 45 2e 42 49 4e } //00 00  \Users\Public\C:\$RECYCLE.BIN
	condition:
		any of ($a_*)
 
}