
rule Backdoor_Win32_NetWiredRC_E{
	meta:
		description = "Backdoor:Win32/NetWiredRC.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {aa aa aa aa aa aa aa 81 } //1
		$a_03_1 = {02 64 8b 0d 18 00 00 00 81 ?? ?? ?? ?? 02 81 } //1
		$a_03_2 = {02 8b 49 30 81 ?? ?? ?? ?? 02 } //1
		$a_01_3 = {02 02 59 02 90 81 } //1
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}