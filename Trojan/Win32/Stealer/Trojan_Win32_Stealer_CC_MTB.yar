
rule Trojan_Win32_Stealer_CC_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f9 8b 4d 90 02 04 d3 e8 c7 05 90 02 08 03 45 90 02 04 33 c7 8b f8 83 fa 90 02 04 75 2c 90 00 } //01 00 
		$a_01_1 = {03 c3 33 ca 33 c8 89 4d } //01 00 
		$a_03_2 = {81 fe 06 0c 00 00 75 05 e8 90 02 04 46 81 fe 35 6b 24 00 7c ea 90 00 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}