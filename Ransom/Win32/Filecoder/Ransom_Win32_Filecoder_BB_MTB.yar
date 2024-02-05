
rule Ransom_Win32_Filecoder_BB_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {62 63 6b 20 34 2e 30 20 32 30 32 30 2f 2f 31 31 2f 36 20 66 69 78 20 35 2e 76 69 72 75 73 20 62 79 20 7a 6e 6b 7a 7a } //01 00 
		$a_81_2 = {2d 4c 49 42 47 43 43 57 33 32 2d 45 48 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_BB_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 66 20 59 6f 75 20 77 61 6e 74 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 20 70 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 75 73 20 6f 6e 20 6a 61 62 62 65 72 3a } //01 00 
		$a_81_1 = {70 61 79 6d 65 70 6c 65 61 73 65 40 73 6a 2e 6d 73 } //01 00 
		$a_81_2 = {6a 75 73 74 66 69 6c 65 2e 74 78 74 } //01 00 
		$a_81_3 = {49 4e 53 54 52 55 43 54 49 4f 4e 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_BB_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 4f 57 5f 54 4f 5f 52 45 54 55 52 4e 5f 46 49 4c 45 53 2e 74 78 74 } //01 00 
		$a_81_1 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //01 00 
		$a_03_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 90 02 05 2e 65 78 65 20 2f 54 20 2f 46 90 00 } //01 00 
		$a_81_3 = {64 6f 6e 27 74 20 68 61 76 65 20 65 6e 6f 75 67 68 20 74 69 6d 65 20 74 6f 20 74 68 69 6e 6b 20 65 61 63 68 20 64 61 79 20 70 61 79 6d 65 6e 74 20 77 69 6c 6c 20 69 6e 63 72 65 61 73 65 20 61 6e 64 20 61 66 74 65 72 20 6f 6e 65 20 77 65 65 6b 20 79 6f 75 72 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}