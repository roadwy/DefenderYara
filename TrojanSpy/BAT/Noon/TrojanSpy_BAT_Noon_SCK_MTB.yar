
rule TrojanSpy_BAT_Noon_SCK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1d 5d 16 fe 01 0d 09 2c 0b 06 08 06 08 91 1f 4b 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanSpy_BAT_Noon_SCK_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Noon.SCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 d6 13 06 11 06 06 6f 3b 00 00 0a fe 04 13 08 11 08 2d 9e } //2
		$a_81_1 = {43 6f 6d 62 6f 42 6f 78 42 69 6e 64 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //2 ComboBoxBind.MainForm.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}