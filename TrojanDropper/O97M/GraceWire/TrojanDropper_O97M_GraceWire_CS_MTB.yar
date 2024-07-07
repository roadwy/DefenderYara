
rule TrojanDropper_O97M_GraceWire_CS_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 43 68 65 63 6b 43 61 72 28 63 61 72 20 41 73 20 4f 62 6a 65 63 74 2c 20 44 72 69 76 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Property Get CheckCar(car As Object, Drive As String)
		$a_01_1 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //1 CheckCar = car.SpecialFolders("" & Drive)
		$a_01_2 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 29 20 41 73 20 53 74 72 69 6e 67 } //1 Public Property Get SpecialFolders() As String
		$a_01_3 = {45 6c 73 65 49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 4e 6f 74 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 54 68 65 6e } //1 ElseIf tooolsetChunkI And Not tooolsetChunkQ Then
		$a_01_4 = {43 68 44 69 72 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 ChDir Dialog4.TextBox3.Tag
		$a_01_5 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 63 20 3c 3e } //1 If tooolsetChunkI And j = Count And c <>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDropper_O97M_GraceWire_CS_MTB_2{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 20 28 22 52 65 73 65 74 5f 52 69 67 68 74 43 6c 69 63 6b 22 29 3a 20 52 75 6e 20 28 4e 61 6d 65 44 54 20 26 20 22 21 4c 6f 61 64 50 6f 70 75 70 22 29 } //1 Run ("Reset_RightClick"): Run (NameDT & "!LoadPopup")
		$a_01_1 = {52 65 67 4b 65 79 52 65 61 64 28 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 42 61 63 4e 61 6d 53 6f 66 74 5c 44 75 74 6f 61 6e 5c 41 75 74 6f 52 65 6e 61 6d 65 22 29 20 3d 20 22 31 22 } //1 RegKeyRead("HKEY_CURRENT_USER\Software\BacNamSoft\Dutoan\AutoRename") = "1"
		$a_03_2 = {3d 20 54 72 75 65 20 54 68 65 6e 20 53 68 65 65 74 73 28 22 53 65 74 74 69 6e 67 22 29 2e 52 61 6e 67 65 28 90 02 05 29 2e 56 61 6c 75 65 20 3d 20 53 68 5f 54 48 56 54 5f 42 58 2e 4e 61 6d 65 90 00 } //1
		$a_01_3 = {53 65 74 20 6d 79 57 53 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set myWS = CreateObject("WScript.Shell")
		$a_01_4 = {52 65 67 4b 65 79 52 65 61 64 20 3d 20 6d 79 57 53 2e 52 65 67 52 65 61 64 28 69 5f 52 65 67 4b 65 79 29 } //1 RegKeyRead = myWS.RegRead(i_RegKey)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}