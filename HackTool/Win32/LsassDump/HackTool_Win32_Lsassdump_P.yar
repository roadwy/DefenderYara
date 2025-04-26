
rule HackTool_Win32_Lsassdump_P{
	meta:
		description = "HackTool:Win32/Lsassdump.P,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 20 61 20 64 75 6d 70 20 77 69 74 68 20 61 20 76 61 6c 69 64 20 73 69 67 6e 61 74 75 72 65 } //1 create a dump with a valid signature
		$a_01_1 = {74 68 65 20 50 49 44 20 6f 66 20 4c 53 41 53 53 } //1 the PID of LSASS
		$a_01_2 = {70 79 70 79 6b 61 74 7a 20 6c 73 61 20 6d 69 6e 69 64 75 6d 70 } //3 pypykatz lsa minidump
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=4
 
}