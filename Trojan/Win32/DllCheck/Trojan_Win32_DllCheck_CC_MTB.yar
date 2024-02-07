
rule Trojan_Win32_DllCheck_CC_MTB{
	meta:
		description = "Trojan:Win32/DllCheck.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fb 55 e6 0c 09 7f 09 43 81 fb e2 dc 48 70 7c e7 } //01 00 
		$a_03_1 = {81 fe 06 0c 00 00 75 05 e8 90 01 04 46 81 fe 35 6b 24 00 7c ea 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}