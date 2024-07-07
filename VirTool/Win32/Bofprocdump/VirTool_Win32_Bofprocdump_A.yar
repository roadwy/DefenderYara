
rule VirTool_Win32_Bofprocdump_A{
	meta:
		description = "VirTool:Win32/Bofprocdump.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 75 6d 70 69 6e 67 20 50 49 44 } //1 Dumping PID
		$a_01_1 = {57 72 6f 74 65 20 64 75 6d 70 20 74 6f 20 66 69 6c 65 } //1 Wrote dump to file
		$a_01_2 = {44 6f 6e 27 74 20 66 6f 72 67 65 74 20 74 6f 20 64 65 6c 65 74 65 } //1 Don't forget to delete
		$a_01_3 = {70 72 6f 63 64 75 6d 70 20 66 61 69 6c 65 64 } //1 procdump failed
		$a_01_4 = {62 6f 66 73 74 6f 70 } //1 bofstop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}