
rule Trojan_Win32_Qakbot_PC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 6c 65 33 34 35 34 2e 64 6c 6c } //01 00  ole3454.dll
		$a_01_1 = {5c 44 6c 6c 5c 6f 75 74 2e 70 64 62 } //01 00  \Dll\out.pdb
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //04 00  DllRegisterServer
		$a_03_3 = {d3 fa 89 15 90 01 04 8b 4d 90 01 01 2b 4d 90 01 01 2b 0d 90 01 04 03 4d 90 01 01 8b 45 90 01 01 d3 f8 33 45 90 01 01 8b 55 90 01 01 8b 0d 90 01 04 d3 fa 33 55 90 01 01 8b 4d 90 01 01 2b 4d 90 01 01 8b 35 90 01 04 d3 e6 33 d6 3b c2 7f 90 00 } //00 00 
		$a_00_4 = {7e 15 00 00 } //4a f6 
	condition:
		any of ($a_*)
 
}