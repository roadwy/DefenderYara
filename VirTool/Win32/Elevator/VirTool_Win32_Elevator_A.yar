
rule VirTool_Win32_Elevator_A{
	meta:
		description = "VirTool:Win32/Elevator.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {64 69 6e 76 6f 6b 65 5c 73 72 63 5c } //1 dinvoke\src\
		$a_81_1 = {72 70 63 63 6c 69 65 6e 74 5c 73 72 63 5c } //1 rpcclient\src\
		$a_81_2 = {6d 61 6e 75 61 6c 6d 61 70 5c 73 72 63 5c } //1 manualmap\src\
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}