
rule Trojan_Win32_AntiAV_CA_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 ff d3 81 fe 12 80 5d 03 7f 15 46 8b c6 99 81 fa 90 02 04 7c e8 7f 07 3d 2f 46 15 1f 72 df 90 00 } //01 00 
		$a_01_1 = {56 65 62 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VebtualProtect
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}