
rule TrojanDropper_Win32_Aenjaris_AMTB{
	meta:
		description = "TrojanDropper:Win32/Aenjaris!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_80_0 = {31 31 31 31 50 72 6f 67 53 74 61 72 74 2e 6e 61 6d 65 } //1111ProgStart.name  1
		$a_80_1 = {33 33 33 33 33 2e 65 78 65 } //33333.exe  1
		$a_80_2 = {38 68 45 2e 39 56 50 } //8hE.9VP  1
		$a_80_3 = {34 73 56 2e 4a 58 33 } //4sV.JX3  1
		$a_80_4 = {75 75 75 25 73 73 73 77 74 74 72 } //uuu%ssswttr  1
		$a_80_5 = {79 71 65 7b 79 71 65 79 79 71 65 79 79 71 65 76 79 71 65 76 79 74 65 76 79 74 65 79 79 76 63 79 79 75 43 74 7b 74 } //yqe{yqeyyqeyyqevyqevytevyteyyvcyyuCt{t  1
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=6
 
}