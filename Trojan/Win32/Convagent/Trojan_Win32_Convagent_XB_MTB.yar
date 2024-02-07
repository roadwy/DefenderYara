
rule Trojan_Win32_Convagent_XB_MTB{
	meta:
		description = "Trojan:Win32/Convagent.XB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 8b 08 89 4d e0 8b 55 f0 8b 02 c1 e0 06 8b 4d f0 8b 11 c1 ea 08 33 c2 8b 4d f0 8b 09 03 c8 8b 45 f8 33 d2 f7 75 e4 8b 45 d8 03 0c 90 03 4d f8 8b 55 e8 8b 02 2b c1 8b 4d e8 89 01 8b 55 f0 8b 45 e8 8b 08 89 0a 81 3d } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}