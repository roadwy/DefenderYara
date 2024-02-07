
rule Ransom_Win64_GoHive_PAA_MTB{
	meta:
		description = "Ransom:Win64/GoHive.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 6f 20 64 65 63 72 79 70 74 20 61 6c 6c 20 74 68 65 20 64 61 74 61 20 6f 72 20 74 6f 20 70 72 65 76 65 6e 74 20 69 74 20 66 72 6f 6d 20 6c 65 61 6b 61 67 65 20 61 74 20 6f 75 72 20 77 65 62 73 69 74 65 } //01 00  To decrypt all the data or to prevent it from leakage at our website
		$a_01_1 = {46 6f 6c 6c 6f 77 20 74 68 65 20 67 75 69 64 65 6c 69 6e 65 73 20 62 65 6c 6f 77 20 74 6f 20 61 76 6f 69 64 20 6c 6f 73 69 6e 67 20 79 6f 75 72 20 64 61 74 61 3a } //01 00  Follow the guidelines below to avoid losing your data:
		$a_01_2 = {59 6f 75 72 20 73 65 6e 73 69 74 69 76 65 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 70 75 62 6c 69 63 6c 79 20 64 69 73 63 6c 6f 73 65 64 } //01 00  Your sensitive data will be publicly disclosed
		$a_01_3 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 64 65 63 72 79 70 74 20 64 61 74 61 } //01 00  Do not try to decrypt data
		$a_01_4 = {44 6f 20 6e 6f 74 20 66 6f 6f 6c 20 79 6f 75 72 73 65 6c 66 2e } //01 00  Do not fool yourself.
		$a_01_5 = {59 6f 75 20 77 69 6c 6c 20 6c 6f 73 65 20 74 68 65 6d 2e } //01 00  You will lose them.
		$a_01_6 = {61 6e 64 20 69 6e 20 6d 61 73 73 20 6d 65 64 69 61 } //00 00  and in mass media
	condition:
		any of ($a_*)
 
}