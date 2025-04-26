
rule TrojanDropper_O97M_GraceWire_BG_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 2b 20 44 72 69 76 65 29 } //1 CheckCar = car.SpecialFolders("" + Drive)
		$a_01_1 = {50 52 50 20 3d 20 22 25 22 20 2b 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 PRP = "%" + UserForm6.TextBox1.Tag
		$a_01_2 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 41 63 74 69 76 65 48 6f 74 62 69 74 2c 20 22 22 20 26 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 22 29 } //1 UserForm6.TextBox3.Tag = car.CheckCar(ActiveHotbit, "" & UserForm6.TextBox3.Tag + "")
		$a_01_3 = {49 66 20 72 65 73 75 6c 74 20 3d 20 52 43 50 4e 44 5f 46 4d 4f 44 5f 4f 4b 20 54 68 65 6e } //1 If result = RCPND_FMOD_OK Then
		$a_03_4 = {4b 69 6c 6c 20 4b 65 79 [0-08] 4e 65 78 74 20 4b 65 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}