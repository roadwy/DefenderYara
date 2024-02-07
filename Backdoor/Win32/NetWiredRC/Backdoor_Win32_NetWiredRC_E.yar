
rule Backdoor_Win32_NetWiredRC_E{
	meta:
		description = "Backdoor:Win32/NetWiredRC.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {aa aa aa aa aa aa aa 81 } //01 00 
		$a_03_1 = {02 64 8b 0d 18 00 00 00 81 90 01 04 02 81 90 00 } //01 00 
		$a_03_2 = {02 8b 49 30 81 90 01 04 02 90 00 } //01 00 
		$a_01_3 = {02 02 59 02 90 81 } //01 00 
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}