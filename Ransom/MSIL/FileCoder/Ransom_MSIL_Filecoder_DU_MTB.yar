
rule Ransom_MSIL_Filecoder_DU_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 54 43 20 41 64 64 72 65 73 73 20 3a } //01 00 
		$a_81_1 = {4c 4f 43 4b 54 48 41 54 } //01 00 
		$a_81_2 = {53 50 4c 49 54 54 54 54 } //01 00 
		$a_81_3 = {73 74 75 62 41 45 53 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //01 00 
		$a_81_5 = {2e 64 73 66 64 73 66 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DU_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 } //Decrypting files  01 00 
		$a_80_1 = {43 6c 6f 73 65 20 63 72 79 70 74 65 72 } //Close crypter  01 00 
		$a_80_2 = {59 6f 75 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 50 61 69 64 20 50 61 72 74 2f 41 6c 6c 20 4f 66 20 59 6f 75 72 20 4f 75 74 73 74 61 6e 64 69 6e 67 20 42 61 6c 61 6e 63 65 } //You Successfully Paid Part/All Of Your Outstanding Balance  01 00 
		$a_80_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 75 73 69 6f 6e 70 61 6b 2e 78 79 7a 2f 6d 61 6c 2f 76 65 72 69 66 79 2e 70 68 70 } //http://www.fusionpak.xyz/mal/verify.php  01 00 
		$a_80_4 = {53 68 6f 75 6c 64 6e 74 20 48 61 76 65 20 54 72 69 65 64 20 54 6f 20 44 65 62 75 67 20 4f 75 72 20 53 6f 66 74 77 61 72 65 } //Shouldnt Have Tried To Debug Our Software  01 00 
		$a_80_5 = {24 31 35 30 20 55 53 44 20 52 65 6d 61 69 6e 69 6e 67 } //$150 USD Remaining  01 00 
		$a_80_6 = {44 65 70 6f 73 69 74 20 46 75 6e 64 73 } //Deposit Funds  01 00 
		$a_80_7 = {43 3a 5c 55 73 65 72 73 5c 53 61 6d 62 32 5c 44 65 73 6b 74 6f 70 5c 44 55 4d 42 2d 6d 61 73 74 65 72 5c 44 55 4d 42 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 44 55 4d 42 2e 70 64 62 } //C:\Users\Samb2\Desktop\DUMB-master\DUMB\obj\Release\DUMB.pdb  00 00 
	condition:
		any of ($a_*)
 
}