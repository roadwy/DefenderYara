
rule Trojan_Win32_Convagent_CC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c 33 0d 90 02 04 2b 4d 0c 81 f1 28 0a dd e4 e9 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}