
rule Worm_Win32_Folxrun_A{
	meta:
		description = "Worm:Win32/Folxrun.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  shell\AutoRun\command
		$a_01_1 = {73 00 74 00 61 00 72 00 74 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 } //01 00  start explorer
		$a_01_2 = {00 66 72 6d 5f 6c 6f 63 6b 00 } //01 00  昀浲江捯k
		$a_01_3 = {43 00 61 00 70 00 74 00 75 00 72 00 65 00 53 00 63 00 72 00 65 00 65 00 6e 00 } //01 00  CaptureScreen
		$a_01_4 = {6d 00 73 00 66 00 6f 00 6c 00 64 00 } //00 00  msfold
		$a_00_5 = {5d 04 00 } //00 d9 
	condition:
		any of ($a_*)
 
}