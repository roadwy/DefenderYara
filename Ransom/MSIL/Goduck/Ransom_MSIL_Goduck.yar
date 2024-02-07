
rule Ransom_MSIL_Goduck{
	meta:
		description = "Ransom:MSIL/Goduck,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7c 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 41 4c 4c 20 49 20 44 45 43 52 59 50 54 20 59 4f 55 52 20 46 49 4c 45 53 20 57 49 54 48 20 20 4d 59 20 20 44 45 43 52 59 50 54 4f 52 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 7c } //0a 00  |                       ALL I DECRYPT YOUR FILES WITH  MY  DECRYPTOR                    |
		$a_81_1 = {50 72 6f 67 72 61 6d 2e 65 78 65 } //00 00  Program.exe
	condition:
		any of ($a_*)
 
}