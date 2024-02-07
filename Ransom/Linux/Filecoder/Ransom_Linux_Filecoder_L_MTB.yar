
rule Ransom_Linux_Filecoder_L_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 44 61 74 61 } //01 00  main.encryptData
		$a_01_1 = {6d 61 69 6e 2e 69 73 50 61 79 65 64 } //01 00  main.isPayed
		$a_01_2 = {6d 61 69 6e 2e 73 65 6c 66 52 65 6d 6f 76 65 } //01 00  main.selfRemove
		$a_01_3 = {63 72 65 61 74 65 41 6e 64 53 68 6f 77 4d 65 73 73 61 67 65 } //01 00  createAndShowMessage
		$a_01_4 = {64 6f 53 6f 6d 65 54 68 69 6e 67 45 6c 73 65 57 69 74 68 44 65 62 75 67 67 65 72 } //00 00  doSomeThingElseWithDebugger
	condition:
		any of ($a_*)
 
}