
rule VirTool_Win32_Bofprocdes_A{
	meta:
		description = "VirTool:Win32/Bofprocdes.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 69 6e 67 20 61 6c 6c 20 68 61 6e 64 6c 65 73 20 69 6e 20 50 49 44 } //1 Killing all handles in PID
		$a_01_1 = {43 6c 6f 73 65 64 20 61 6c 6c 20 68 61 6e 64 6c 65 73 20 69 6e 20 70 69 64 } //1 Closed all handles in pid
		$a_01_2 = {6b 69 6c 6c 69 74 20 66 61 69 6c 65 64 } //1 killit failed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}