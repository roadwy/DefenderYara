
rule Trojan_BAT_AveMaria_NECY_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_01_0 = {35 36 31 65 37 61 39 33 2d 64 32 32 32 2d 34 63 62 64 2d 61 62 63 30 2d 35 39 63 37 30 65 38 62 37 34 65 64 } //5 561e7a93-d222-4cbd-abc0-59c70e8b74ed
		$a_01_1 = {5f 32 30 34 38 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 2e 52 75 6c 65 73 4f 66 54 68 65 47 61 6d 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //5 _2048WindowsFormsApp.RulesOfTheGameForm.resources
		$a_01_2 = {6d 61 70 53 69 7a 65 35 78 35 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d 5f 43 6c 69 63 6b } //5 mapSize5x5ToolStripMenuItem_Click
		$a_01_3 = {41 6c 6c 53 63 6f 72 65 73 46 6f 72 6d 5f 4c 6f 61 64 } //2 AllScoresForm_Load
		$a_01_4 = {67 65 74 5f 74 65 78 74 5f 78 5f 72 70 6d 5f 73 70 65 63 } //2 get_text_x_rpm_spec
		$a_01_5 = {43 41 53 43 58 } //1 CASCX
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=20
 
}