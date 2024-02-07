
rule Ransom_MSIL_WPlague_DB_MTB{
	meta:
		description = "Ransom:MSIL/WPlague.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } //01 00  Rasomware2.0
		$a_81_1 = {44 45 43 52 59 50 54 20 46 49 4c 45 53 } //01 00  DECRYPT FILES
		$a_81_2 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Rasomware2._0.Properties.Resources
		$a_81_3 = {6f 6e 6c 79 20 77 69 74 68 20 6f 75 72 20 6b 65 79 20 77 65 20 63 61 6e 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 } //01 00  only with our key we can recover your files
		$a_81_4 = {4e 6f 77 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 63 6f 6e 74 61 63 74 20 62 6c 34 61 63 6b 23 31 33 33 37 20 6f 6e 20 74 68 65 20 64 69 73 63 6f 72 64 20 61 73 6b 69 6e 67 20 66 6f 72 20 74 68 65 20 64 65 63 72 79 70 74 20 6b 65 79 } //00 00  Now you need to contact bl4ack#1337 on the discord asking for the decrypt key
	condition:
		any of ($a_*)
 
}