
rule Ransom_Win64_SolasoCrypt_AJY_MSR{
	meta:
		description = "Ransom:Win64/SolasoCrypt.AJY!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {5f 5f 52 45 41 44 5f 4d 45 5f 50 4c 45 41 53 45 2e 74 78 74 5f 5f } //01 00  __READ_ME_PLEASE.txt__
		$a_81_1 = {48 65 6c 6c 6f 2c 20 79 6f 75 20 63 61 6e 74 20 6f 70 65 6e 20 79 6f 75 72 20 66 69 6c 65 73 2e } //01 00  Hello, you cant open your files.
		$a_81_2 = {54 68 65 20 6f 6e 6c 79 20 77 61 79 20 74 6f 20 6f 70 65 6e 20 61 6e 64 20 75 73 65 20 79 6f 75 72 20 66 69 6c 65 73 20 61 67 61 69 6e 20 69 73 20 75 73 69 6e 67 20 61 20 74 6f 6f 6c 20 74 68 61 74 20 6f 6e 6c 79 20 77 65 20 68 61 76 65 2e } //01 00  The only way to open and use your files again is using a tool that only we have.
		$a_81_3 = {65 6d 61 69 6c 3a 20 73 61 6d 6d 79 37 30 70 5f 79 36 31 6d 40 62 75 78 6f 64 2e 63 6f 6d } //01 00  email: sammy70p_y61m@buxod.com
		$a_81_4 = {43 3a 5c 55 73 65 72 73 5c 4d 41 52 49 4f 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 45 4e 43 52 49 50 54 41 52 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 45 4e 43 52 49 50 54 41 52 2e 70 64 62 } //01 00  C:\Users\MARIO\source\repos\ENCRIPTAR\x64\Release\ENCRIPTAR.pdb
		$a_81_5 = {2e 73 6f 6c 61 73 6f } //00 00  .solaso
	condition:
		any of ($a_*)
 
}