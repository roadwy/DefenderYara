
rule Ransom_Win32_Spade_DB_MTB{
	meta:
		description = "Ransom:Win32/Spade.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //01 00  wbadmin delete catalog -quiet
		$a_81_1 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 20 63 75 72 72 65 6e 74 70 72 6f 66 69 6c 65 20 73 74 61 74 65 20 6f 66 66 } //01 00  netsh advfirewall set  currentprofile state off
		$a_81_2 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 49 44 6b 2e 74 78 74 } //01 00  ProgramData\IDk.txt
		$a_81_3 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 70 75 62 6b 2e 74 78 74 } //01 00  ProgramData\pubk.txt
		$a_81_4 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 45 31 4d 55 52 43 66 53 } //01 00  https://pastebin.com/raw/E1MURCfS
		$a_81_5 = {55 73 65 72 73 5c 4c 65 67 69 6f 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 63 75 72 6c 5c 52 65 6c 65 61 73 65 5c 63 75 72 6c 2e 70 64 62 } //01 00  Users\Legion\source\repos\curl\Release\curl.pdb
		$a_81_6 = {52 65 61 64 2d 46 6f 72 2d 44 65 63 72 79 70 74 2e 48 54 41 } //01 00  Read-For-Decrypt.HTA
		$a_81_7 = {21 49 4e 46 4f 2e 48 54 41 } //00 00  !INFO.HTA
	condition:
		any of ($a_*)
 
}