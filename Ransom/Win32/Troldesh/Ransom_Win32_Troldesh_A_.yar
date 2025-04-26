
rule Ransom_Win32_Troldesh_A_{
	meta:
		description = "Ransom:Win32/Troldesh.A!!Troldesh.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {57 61 6c 6b 65 72 3a } //1 Walker:
		$a_00_1 = {57 61 74 63 68 65 72 3a } //1 Watcher:
		$a_00_2 = {77 62 32 7c 63 64 72 7c 73 72 77 7c 70 37 62 7c 6f 64 6d 7c 6d 64 66 7c 70 37 63 7c 33 66 72 7c } //1 wb2|cdr|srw|p7b|odm|mdf|p7c|3fr|
		$a_00_3 = {72 65 67 2e 70 68 70 00 } //1
		$a_00_4 = {73 65 6e 64 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 63 6f 64 65 3a } //1 send the following code:
		$a_00_5 = {64 65 73 6b 74 6f 70 2e 69 6e 69 7c 62 6f 6f 74 2e 69 6e 69 7c 42 4f 4f 54 2e 49 4e 49 } //1 desktop.ini|boot.ini|BOOT.INI
		$a_00_6 = {2d 2d 69 67 6e 6f 72 65 2d 6d 69 73 73 69 6e 67 2d 74 6f 72 72 63 } //1 --ignore-missing-torrc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}