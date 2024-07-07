
rule TrojanDownloader_O97M_Ursnif_AEF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AEF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {2e 6a 70 67 22 29 } //1 .jpg")
		$a_01_1 = {3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 22 78 66 65 2e 70 6e 67 22 } //1 = "C:\users\Public\" + "xfe.png"
		$a_01_2 = {50 72 69 76 61 74 65 20 53 75 62 20 73 6b 75 69 64 5f 43 68 61 6e 67 65 28 29 } //1 Private Sub skuid_Change()
		$a_01_3 = {26 20 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 33 29 } //1 & ListBox1.List(3)
		$a_01_4 = {3d 20 4c 65 6e 28 22 5a 30 30 22 29 20 54 68 65 6e } //1 = Len("Z00") Then
		$a_01_5 = {2b 20 54 72 69 6d 28 22 61 22 29 20 2b 20 54 72 69 6d 28 22 6d 22 29 29 } //1 + Trim("a") + Trim("m"))
		$a_01_6 = {53 68 65 6c 6c 52 75 6e 6e 65 72 2e 52 75 6e 20 56 61 72 45 78 51 75 65 72 79 20 26 20 52 65 66 41 72 72 61 79 } //1 ShellRunner.Run VarExQuery & RefArray
		$a_01_7 = {50 75 62 6c 69 63 20 53 75 62 20 4f 70 74 69 6f 6e 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //1 Public Sub OptionButton1_Click()
		$a_01_8 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 29 } //1 ListBox1.AddItem (CommandButton1.Tag)
		$a_01_9 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 43 68 65 63 6b 42 6f 78 31 2e 54 61 67 29 } //1 ListBox1.AddItem (CheckBox1.Tag)
		$a_01_10 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 49 6d 61 67 65 31 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 29 } //1 ListBox1.AddItem (Image1.ControlTipText)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}