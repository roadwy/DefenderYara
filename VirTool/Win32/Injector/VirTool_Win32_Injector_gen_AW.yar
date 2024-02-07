
rule VirTool_Win32_Injector_gen_AW{
	meta:
		description = "VirTool:Win32/Injector.gen!AW,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 00 53 00 45 00 54 00 20 00 4e 00 4f 00 44 00 33 00 32 00 20 00 61 00 6e 00 64 00 20 00 53 00 6f 00 70 00 68 00 6f 00 73 00 20 00 61 00 72 00 65 00 20 00 61 00 20 00 62 00 75 00 6e 00 63 00 68 00 20 00 6f 00 66 00 20 00 66 00 61 00 67 00 67 00 6f 00 74 00 73 00 21 00 } //01 00  ESET NOD32 and Sophos are a bunch of faggots!
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c } //00 00  cmd.exe /c del
	condition:
		any of ($a_*)
 
}