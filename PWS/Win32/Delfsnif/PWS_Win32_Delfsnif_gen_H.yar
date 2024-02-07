
rule PWS_Win32_Delfsnif_gen_H{
	meta:
		description = "PWS:Win32/Delfsnif.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 61 6d 65 65 78 65 3a } //01 00  nameexe:
		$a_01_1 = {70 61 73 73 3a 00 00 00 } //03 00 
		$a_00_2 = {69 66 20 65 78 69 73 74 } //03 00  if exist
		$a_00_3 = {61 62 6f 75 74 3a 62 6c 61 6e 6b } //01 00  about:blank
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //03 00  WriteProcessMemory
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //03 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_6 = {47 00 65 00 6e 00 65 00 72 00 69 00 63 00 20 00 48 00 6f 00 73 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 33 00 32 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //00 00  Generic Host Process for Win32 Services
	condition:
		any of ($a_*)
 
}