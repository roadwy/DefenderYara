
rule VirTool_Win32_VBInject_gen_B{
	meta:
		description = "VirTool:Win32/VBInject.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {45 41 44 57 52 49 50 72 6f 6a 65 63 74 31 00 45 58 45 43 55 54 45 } //05 00  䅅坄䥒牐橯捥ㅴ䔀䕘啃䕔
		$a_01_1 = {6d 6f 64 49 6e 6a 65 63 74 } //02 00  modInject
		$a_01_2 = {6d 6f 64 43 72 79 70 74 } //02 00  modCrypt
		$a_01_3 = {6d 6f 64 50 72 6f 74 65 63 74 } //02 00  modProtect
		$a_01_4 = {6d 6f 64 4d 61 69 6e } //01 00  modMain
		$a_00_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //09 00  WriteProcessMemory
		$a_03_6 = {f5 04 00 00 00 f5 00 30 00 00 6c 90 01 02 6c 90 01 02 6c 90 01 02 5e 90 01 04 71 90 01 02 3c 6c 90 01 02 71 90 01 02 6c 90 01 02 f5 00 00 00 00 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}