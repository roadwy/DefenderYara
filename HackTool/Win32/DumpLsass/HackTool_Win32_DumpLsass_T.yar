
rule HackTool_Win32_DumpLsass_T{
	meta:
		description = "HackTool:Win32/DumpLsass.T,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 47 6f 74 20 6c 73 61 73 73 2e 65 78 65 20 50 49 44 3a } //1 [+] Got lsass.exe PID:
		$a_01_1 = {5b 2b 5d 20 6c 73 61 73 73 20 64 75 6d 70 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //1 [+] lsass dumped successfully!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}