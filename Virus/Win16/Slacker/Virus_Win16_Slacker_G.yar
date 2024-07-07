
rule Virus_Win16_Slacker_G{
	meta:
		description = "Virus:Win16/Slacker.G,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 54 4d 50 5c 22 20 2b 20 90 02 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 43 6f 70 79 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d 90 00 } //1
		$a_00_1 = {2e 4c 69 6e 65 73 28 31 2c 20 31 29 20 3c 3e 20 22 27 4f 4f 4f 22 20 54 68 65 6e } //1 .Lines(1, 1) <> "'OOO" Then
		$a_00_2 = {53 61 76 65 41 73 20 46 69 6c 65 6e 61 6d 65 3a 3d 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 2b 20 22 5c 42 6f 6f 6b 31 2e 22 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 78 6c 4e 6f 72 6d 61 6c } //1 SaveAs Filename:=Application.StartupPath + "\Book1.", FileFormat:=xlNormal
		$a_02_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 4b 65 79 20 22 7b 46 35 7d 22 2c 20 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 76 74 48 69 64 65 52 6f 77 22 90 02 15 41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 4b 65 79 20 22 7b 46 36 7d 22 2c 20 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 76 74 53 68 6f 77 52 6f 77 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}