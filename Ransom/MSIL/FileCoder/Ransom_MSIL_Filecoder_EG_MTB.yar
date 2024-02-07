
rule Ransom_MSIL_Filecoder_EG_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 45 41 44 5f 4d 45 2e 68 74 6d 6c } //01 00  READ_ME.html
		$a_81_1 = {68 74 74 70 3a 2f 2f 74 72 75 73 74 6d 6f 72 64 6f 72 2e 70 77 2f 72 65 61 64 6d 65 2e 70 68 70 3f 69 64 3d } //01 00  http://trustmordor.pw/readme.php?id=
		$a_81_2 = {4e 4f 54 48 45 52 53 50 41 43 45 5f 55 53 45 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  NOTHERSPACE_USE.Properties.Resources
		$a_81_3 = {57 65 62 5c 63 72 79 70 74 5c 6a 6f 69 73 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 4e 4f 54 48 45 52 53 50 41 43 45 5f 55 53 45 2e 70 64 62 } //01 00  Web\crypt\joise\obj\Debug\NOTHERSPACE_USE.pdb
		$a_81_4 = {4e 4f 54 48 45 52 53 50 41 43 45 5f 55 53 45 2e 65 78 65 } //00 00  NOTHERSPACE_USE.exe
	condition:
		any of ($a_*)
 
}