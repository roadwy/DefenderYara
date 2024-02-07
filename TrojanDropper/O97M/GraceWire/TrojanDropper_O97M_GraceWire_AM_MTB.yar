
rule TrojanDropper_O97M_GraceWire_AM_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 2e 64 6c 22 20 2b 20 22 6c 22 } //01 00  & ".dl" + "l"
		$a_01_1 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c 63 6f 6e 74 72 61 63 74 5f 22 } //01 00  UserForm6.TextBox3.Tag + "\contract_"
		$a_01_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 43 6f 70 79 } //01 00  ThisWorkbook.Sheets.Copy
		$a_01_3 = {23 49 66 20 56 42 41 37 20 54 68 65 6e } //01 00  #If VBA7 Then
		$a_01_4 = {46 4d 4f 44 5f 53 79 73 74 2e 65 6d 5f 43 72 65 61 74 65 28 53 79 73 74 65 6d 29 } //00 00  FMOD_Syst.em_Create(System)
	condition:
		any of ($a_*)
 
}