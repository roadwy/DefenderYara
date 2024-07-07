
rule VirTool_Win32_Bofpless_A{
	meta:
		description = "VirTool:Win32/Bofpless.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 41 65 c6 44 24 42 74 c6 44 24 43 43 c6 44 24 44 75 c6 44 24 45 72 c6 44 24 46 72 c6 44 24 } //1
		$a_01_1 = {c6 44 24 4b 68 c6 44 24 4c 72 c6 44 24 4d 65 c6 44 24 4e 61 c6 44 24 4f 64 c6 44 24 50 00 48 8d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}