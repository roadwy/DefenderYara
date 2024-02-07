
rule Trojan_Win32_Zbot_CQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {88 1f 00 17 8a 3e 00 3f 81 ef 78 5f 0f 00 81 c7 79 5f 0f 00 81 ee b2 3d 06 00 81 c6 b3 3d 06 00 } //02 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}