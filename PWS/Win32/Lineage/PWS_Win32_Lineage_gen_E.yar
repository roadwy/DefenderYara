
rule PWS_Win32_Lineage_gen_E{
	meta:
		description = "PWS:Win32/Lineage.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 62 61 74 00 00 6f 70 65 6e } //1
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_01_3 = {33 46 44 45 42 31 37 31 2d 38 46 38 36 2d 39 35 35 38 2d 30 30 30 31 2d 36 39 42 38 44 42 35 35 33 36 38 33 } //1 3FDEB171-8F86-9558-0001-69B8DB553683
		$a_01_4 = {73 79 73 74 65 6d 33 32 5c 73 79 73 6a 70 69 65 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}