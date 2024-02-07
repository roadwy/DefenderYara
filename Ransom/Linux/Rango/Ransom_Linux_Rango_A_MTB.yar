
rule Ransom_Linux_Rango_A_MTB{
	meta:
		description = "Ransom:Linux/Rango.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 45 6e 63 72 79 70 74 } //01 00  main.Encrypt
		$a_01_1 = {4c 75 61 6e 53 69 6c 76 65 69 72 61 53 6f 75 7a 61 2f 72 61 6e 67 6f 77 61 72 65 2f 65 78 70 6c 6f 72 65 72 2e 4d 61 70 46 69 6c 65 73 } //01 00  LuanSilveiraSouza/rangoware/explorer.MapFiles
		$a_01_2 = {2f 72 61 6e 67 6f 77 61 72 65 2f 6b 65 79 67 65 6e 2e 47 65 6e 65 72 61 74 65 4b 65 79 } //01 00  /rangoware/keygen.GenerateKey
		$a_01_3 = {66 69 6c 65 70 61 74 68 2e 57 61 6c 6b } //01 00  filepath.Walk
		$a_01_4 = {64 69 72 74 79 4c 6f 63 6b 65 64 } //00 00  dirtyLocked
	condition:
		any of ($a_*)
 
}