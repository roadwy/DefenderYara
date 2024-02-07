
rule Ransom_Win64_Ryuk_PA_MTB{
	meta:
		description = "Ransom:Win64/Ryuk.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 79 00 75 00 6b 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  RyukReadMe.txt
		$a_01_1 = {52 00 79 00 75 00 6b 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  RyukReadMe.html
		$a_01_2 = {55 00 4e 00 49 00 51 00 55 00 45 00 5f 00 49 00 44 00 5f 00 44 00 4f 00 5f 00 4e 00 4f 00 54 00 5f 00 52 00 45 00 4d 00 4f 00 56 00 45 00 } //01 00  UNIQUE_ID_DO_NOT_REMOVE
		$a_01_3 = {2e 00 52 00 59 00 4b 00 } //01 00  .RYK
		$a_01_4 = {6b 00 65 00 79 00 73 00 74 00 6f 00 72 00 61 00 67 00 65 00 32 00 } //01 00  keystorage2
		$a_01_5 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 } //00 00  taskkill
		$a_01_6 = {00 67 } //16 00  最
	condition:
		any of ($a_*)
 
}