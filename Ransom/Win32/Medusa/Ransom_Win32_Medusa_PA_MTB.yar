
rule Ransom_Win32_Medusa_PA_MTB{
	meta:
		description = "Ransom:Win32/Medusa.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 4e 43 52 59 50 54 45 44 } //01 00  ENCRYPTED
		$a_01_1 = {4d 45 44 55 53 41 20 44 45 43 52 59 50 54 4f 52 } //01 00  MEDUSA DECRYPTOR
		$a_01_2 = {47 3a 5c 4d 65 64 75 73 61 5c 52 65 6c 65 61 73 65 5c 67 61 7a 65 2e 70 64 62 } //01 00  G:\Medusa\Release\gaze.pdb
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 46 69 6c 65 } //01 00  powershell -executionpolicy bypass -File
		$a_01_4 = {50 55 42 4c 49 43 20 4b 45 59 } //00 00  PUBLIC KEY
	condition:
		any of ($a_*)
 
}