
rule Virus_Win16_Slacker_gen_A{
	meta:
		description = "Virus:Win16/Slacker.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 77 32 2e 4c 69 6e 65 73 28 31 2c 20 31 29 20 3c 3e 20 22 27 4f 4f 4f 22 20 54 68 65 6e } //1 If w2.Lines(1, 1) <> "'OOO" Then
		$a_01_1 = {49 66 20 55 43 61 73 65 28 44 69 72 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 2b 20 22 5c 62 6f 6f 6b 31 2e 22 29 29 20 3c 3e 20 22 42 4f 4f 4b 31 22 20 54 68 65 6e } //1 If UCase(Dir(Application.StartupPath + "\book1.")) <> "BOOK1" Then
		$a_01_2 = {78 6c 43 4d 2e 49 6e 73 65 72 74 4c 69 6e 65 73 20 31 2c 20 77 31 2e 4c 69 6e 65 73 28 31 2c 20 77 31 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 29 } //1 xlCM.InsertLines 1, w1.Lines(1, w1.CountOfLines)
		$a_01_3 = {78 6c 57 42 2e 53 61 76 65 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 2b 20 22 5c 42 6f 6f 6b 31 2e 22 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 78 6c 4e 6f 72 6d 61 6c 2c 20 41 64 64 54 6f 4d 72 75 3a 3d 46 61 6c 73 65 } //1 xlWB.SaveAs Filename:=Application.StartupPath + "\Book1.", FileFormat:=xlNormal, AddToMru:=False
		$a_01_4 = {6d 46 69 6c 65 4e 61 6d 65 20 3d 20 22 43 3a 5c 54 4d 50 5c 22 20 2b 20 6f 6c 64 6e 61 6d 65 } //1 mFileName = "C:\TMP\" + oldname
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}