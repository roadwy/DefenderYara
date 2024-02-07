
rule Trojan_Win32_Andromeda_CH_MTB{
	meta:
		description = "Trojan:Win32/Andromeda.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f7 8d 3c 10 33 f7 2b ce 8b f1 c1 ee 05 03 35 90 02 04 8b f9 c1 e7 04 03 3d 90 02 04 33 f7 8d 3c 08 33 f7 2b d6 05 90 02 04 83 6d 90 02 04 75 b7 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}