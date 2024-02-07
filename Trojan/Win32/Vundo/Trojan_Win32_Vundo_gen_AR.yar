
rule Trojan_Win32_Vundo_gen_AR{
	meta:
		description = "Trojan:Win32/Vundo.gen!AR,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {77 00 73 00 63 00 6e 00 74 00 66 00 79 00 5f 00 6d 00 74 00 78 00 } //0a 00  wscntfy_mtx
		$a_01_1 = {38 35 2e 31 32 2e 34 33 2e } //0a 00  85.12.43.
		$a_01_2 = {6d 75 6b 6f 7a 6f 72 61 70 61 } //0a 00  mukozorapa
		$a_01_3 = {41 00 70 00 70 00 49 00 6e 00 69 00 74 00 5f 00 44 00 4c 00 4c 00 73 00 } //01 00  AppInit_DLLs
		$a_01_4 = {2f 66 6f 72 6d 2f 69 6e 64 65 78 2e 68 74 6d 6c } //01 00  /form/index.html
		$a_01_5 = {75 72 6f 6c 65 64 75 70 2e 63 6f 6d } //01 00  uroledup.com
		$a_01_6 = {52 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 } //01 00  Rundll32.exe "
	condition:
		any of ($a_*)
 
}