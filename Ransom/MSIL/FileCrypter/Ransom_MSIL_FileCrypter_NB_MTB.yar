
rule Ransom_MSIL_FileCrypter_NB_MTB{
	meta:
		description = "Ransom:MSIL/FileCrypter.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 61 63 6b 65 72 32 } //01 00  hacker2
		$a_81_1 = {79 6f 75 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 70 6f 77 65 72 66 75 6c 20 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 20 52 61 6e 73 6f 6d 77 61 72 65 2f 44 6f 78 77 61 72 65 } //01 00  you are encrypted with powerful military grade Ransomware/Doxware
		$a_81_2 = {70 61 79 20 75 73 20 24 34 2e 35 20 4d 69 6c 6c 69 6f 6e 20 6f 66 20 42 69 74 63 6f 69 6e 20 77 69 74 68 69 6e 20 35 32 20 68 6f 75 72 73 } //01 00  pay us $4.5 Million of Bitcoin within 52 hours
		$a_81_3 = {59 4f 55 52 20 52 45 50 55 54 41 54 49 4f 4e 20 57 49 4c 4c 20 42 45 20 4f 56 45 52 } //01 00  YOUR REPUTATION WILL BE OVER
		$a_81_4 = {2e 4e 69 62 69 72 75 } //01 00  .Nibiru
		$a_81_5 = {59 4f 55 20 48 41 56 45 20 42 45 45 4e 20 48 41 43 4b 45 44 } //01 00  YOU HAVE BEEN HACKED
		$a_81_6 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 54 72 61 6e 73 66 65 72 65 64 20 54 6f 20 48 61 63 6b 65 72 73 20 52 65 6d 6f 74 65 20 53 65 72 76 65 72 } //00 00  All Your Files Transfered To Hackers Remote Server
		$a_00_7 = {5d 04 00 00 2a } //4d 04 
	condition:
		any of ($a_*)
 
}