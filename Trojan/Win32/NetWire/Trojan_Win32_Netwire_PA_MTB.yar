
rule Trojan_Win32_Netwire_PA_MTB{
	meta:
		description = "Trojan:Win32/Netwire.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c2 83 e0 03 8a 88 90 01 04 8d 86 90 01 04 03 c2 30 8a 90 01 04 83 e0 03 30 8a 90 01 04 0f b6 80 90 01 04 30 82 90 01 04 8d 87 90 01 04 03 c2 83 e0 03 0f b6 80 90 01 04 30 82 90 01 04 8d 83 90 01 04 03 c2 83 e0 03 0f b6 80 90 01 04 30 82 90 01 04 8b 45 fc 8d 80 90 01 04 03 c2 83 e0 03 0f b6 80 90 01 04 30 82 90 01 04 83 c2 06 81 fa 90 01 02 00 00 0f 82 90 00 } //01 00 
		$a_02_1 = {51 6a 40 68 90 01 02 00 00 68 90 01 04 ff d0 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}