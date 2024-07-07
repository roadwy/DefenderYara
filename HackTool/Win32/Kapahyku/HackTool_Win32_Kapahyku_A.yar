
rule HackTool_Win32_Kapahyku_A{
	meta:
		description = "HackTool:Win32/Kapahyku.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4b 52 54 20 73 65 74 74 69 6e 67 73 5c 52 65 73 65 74 } //SOFTWARE\KRT settings\Reset  1
		$a_80_1 = {4b 41 53 50 45 52 53 4b 59 20 52 45 53 45 54 20 54 52 49 41 4c } //KASPERSKY RESET TRIAL  1
		$a_80_2 = {66 6f 72 75 6d 2e 72 75 2d 62 6f 61 72 64 } //forum.ru-board  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}