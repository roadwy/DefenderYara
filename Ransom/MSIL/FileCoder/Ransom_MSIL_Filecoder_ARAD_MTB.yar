
rule Ransom_MSIL_Filecoder_ARAD_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_80_0 = {5c 5f 5f 5f 52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 5f 5f 2e 53 6f 6c 6f 67 79 2e 74 78 74 } //\___RECOVER__FILES__.Sology.txt  02 00 
		$a_80_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //All of your files have been encrypted.  02 00 
		$a_80_2 = {33 31 68 53 57 6f 56 64 5a 4a 67 78 74 61 69 53 58 52 71 62 54 73 45 77 56 4e 77 32 76 76 43 51 74 59 } //31hSWoVdZJgxtaiSXRqbTsEwVNw2vvCQtY  00 00 
	condition:
		any of ($a_*)
 
}