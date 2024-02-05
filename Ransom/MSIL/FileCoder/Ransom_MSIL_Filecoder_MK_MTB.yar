
rule Ransom_MSIL_Filecoder_MK_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_1 = {63 6f 6d 70 6f 6e 65 6e 74 2f 61 70 70 2e 78 61 6d 6c } //01 00 
		$a_81_2 = {48 61 63 6b 65 61 64 6f 20 50 75 74 61 } //01 00 
		$a_81_3 = {43 79 70 74 65 64 52 65 61 64 79 2e 69 6e 69 } //01 00 
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00 
		$a_81_5 = {63 6f 6d 70 6f 6e 65 6e 74 2f 6d 61 69 6e 77 69 6e 64 6f 77 2e 78 61 6d 6c } //00 00 
		$a_00_6 = {78 b5 00 00 05 } //00 05 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_MK_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 61 6e 73 6f 6d 65 20 57 61 72 65 } //Ransome Ware  01 00 
		$a_80_1 = {52 61 6e 73 6f 6d 65 20 57 61 72 65 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //Ransome Ware.g.resources  01 00 
		$a_80_2 = {52 61 6e 73 6f 6d 65 5f 57 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Ransome_Ware.Properties.Resources  01 00 
		$a_80_3 = {59 6f 75 72 20 57 69 6e 64 6f 77 73 20 43 6f 6d 70 75 74 65 72 20 48 61 73 20 43 6f 6e 74 72 61 63 6b 65 64 } //Your Windows Computer Has Contracked  01 00 
		$a_80_4 = {43 6f 72 6e 61 6f 20 56 69 72 75 73 20 50 6c 65 61 73 65 20 53 65 61 6e 64 20 44 69 61 73 63 6f 72 64 20 4e 69 74 72 6f } //Cornao Virus Please Seand Diascord Nitro  00 00 
		$a_00_5 = {78 7c 01 } //00 07 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_MK_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 65 61 64 4d 45 2d 44 65 63 72 79 70 74 2e 74 78 74 } //ReadME-Decrypt.txt  01 00 
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 70 61 78 66 75 6c 2e 63 6f 6d } //https://paxful.com  01 00 
		$a_80_2 = {6d 61 69 6c 74 6f 3a 4d 52 45 6e 63 70 74 6f 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //mailto:MREncptor@protonmail.com  01 00 
		$a_80_3 = {41 6c 6c 20 79 6f 75 72 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 69 73 20 6c 6f 63 6b 65 64 20 57 69 74 68 20 53 74 72 6f 6e 67 20 52 61 6e 64 73 6f 6d 77 61 72 65 } //All your information is locked With Strong Randsomware  01 00 
		$a_80_4 = {57 65 20 6f 6e 6c 79 20 41 63 63 65 70 74 20 42 69 74 63 6f 69 6e } //We only Accept Bitcoin  01 00 
		$a_80_5 = {43 6f 73 74 20 46 6f 72 20 59 6f 75 72 20 41 6c 6c 20 44 61 74 61 20 44 65 63 72 79 70 74 } //Cost For Your All Data Decrypt  01 00 
		$a_80_6 = {59 6f 75 20 41 72 65 20 43 72 79 70 74 65 64 } //You Are Crypted  01 00 
		$a_80_7 = {41 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 6c 6f 63 6b 65 64 20 75 73 } //All your data has been locked us  01 00 
		$a_80_8 = {57 65 20 57 69 6c 6c 20 44 65 6c 65 74 65 20 59 6f 75 72 20 44 65 63 72 79 70 74 20 4b 65 79 } //We Will Delete Your Decrypt Key  01 00 
		$a_80_9 = {4e 6f 20 4d 6f 6e 65 79 20 21 20 4e 6f 20 44 65 63 72 79 70 74 69 6f 6e } //No Money ! No Decryption  01 00 
		$a_80_10 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin.exe delete shadows /all /quiet  00 00 
		$a_00_11 = {7e 15 00 00 25 } //f2 48 
	condition:
		any of ($a_*)
 
}