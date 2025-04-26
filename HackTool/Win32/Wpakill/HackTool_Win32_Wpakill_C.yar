
rule HackTool_Win32_Wpakill_C{
	meta:
		description = "HackTool:Win32/Wpakill.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 77 2d 57 47 41 } //1 Chew-WGA
		$a_01_1 = {3c 52 75 6e 3e 61 75 74 6f 72 75 6e 2e 65 78 65 3c 2f 52 75 6e 3e } //1 <Run>autorun.exe</Run>
		$a_01_2 = {3c 70 69 64 3e 42 44 36 42 33 31 39 43 2d 38 37 37 38 2d 34 42 42 37 2d 41 31 35 36 2d 45 43 42 37 30 45 36 32 31 31 37 34 3c 2f 70 69 64 3e } //1 <pid>BD6B319C-8778-4BB7-A156-ECB70E621174</pid>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}