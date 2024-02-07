
rule Trojan_Win32_SpyStealer_AN_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 28 8b 55 08 03 55 fc 0f be 1a e8 90 02 04 33 d8 8b 45 08 03 45 fc 88 18 6a 00 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}