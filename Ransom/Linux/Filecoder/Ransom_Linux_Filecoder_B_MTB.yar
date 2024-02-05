
rule Ransom_Linux_Filecoder_B_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {21 4e 45 57 53 5f 46 4f 52 5f 53 54 4a 21 2e 74 78 74 } //01 00 
		$a_00_1 = {2e 73 74 6a 38 38 38 } //01 00 
		$a_00_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 66 75 6c 6c 79 20 43 52 59 50 54 45 44 } //01 00 
		$a_00_3 = {67 5f 52 61 6e 73 6f 6d 48 65 61 64 65 72 } //01 00 
		$a_00_4 = {21 4e 4f 54 49 43 45 5f 46 4f 52 5f 50 45 54 52 41 4d 49 4e 41 21 2e 74 58 74 } //01 00 
		$a_00_5 = {2e 70 33 74 72 34 6d 31 6e 34 } //01 00 
		$a_00_6 = {65 6e 63 72 79 70 74 5f 77 6f 72 6b 65 72 } //01 00 
		$a_00_7 = {e8 69 e3 00 00 48 83 c4 10 89 45 cc 83 7d cc 00 0f 85 af 00 00 00 48 8d 3d 12 ac 02 00 e8 0d fc ff ff 48 8b 85 e0 e8 ff ff 48 8b 95 e8 e8 ff ff 48 89 05 38 ae 02 00 48 89 15 39 ae 02 00 48 8b 85 f0 e8 ff ff 48 8b 95 f8 e8 ff ff 48 89 05 2c ae 02 00 48 89 15 2d ae 02 00 48 8b 95 78 ee ff ff 48 8d 85 c0 ef ff ff 48 89 c6 48 8d 3d fd ab 02 00 e8 dd fc ff ff 48 8d 3d b1 ab 02 00 e8 fc fa ff ff c7 45 dc 01 00 00 00 48 8d 85 70 ee ff ff } //00 00 
		$a_00_8 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}