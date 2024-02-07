
rule Trojan_Win32_Zbot_CD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 85 20 fe ff ff 28 01 00 00 c6 85 10 fe ff ff 61 c6 85 11 fe ff ff 76 c6 85 12 fe ff ff 61 c6 85 13 fe ff ff 73 c6 85 14 fe ff ff 74 c6 85 15 fe ff ff 73 c6 85 16 fe ff ff 76 c6 85 17 fe ff ff 63 c6 85 18 fe ff ff 2e c6 85 19 fe ff ff 65 c6 85 1a fe ff ff 78 c6 85 1b fe ff ff 65 c6 85 1c fe ff ff 00 8d 85 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}