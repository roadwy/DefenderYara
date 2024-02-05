
rule Trojan_Win32_Zbot_V_MTB{
	meta:
		description = "Trojan:Win32/Zbot.V!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0b 8b 55 f8 81 ea 82 f0 53 75 03 da 8b 03 c1 c0 0f 83 e0 13 03 c8 4f 89 0e ba cc c3 f5 dd 81 f2 c8 c3 f5 dd } //01 00 
		$a_01_1 = {81 ea ec 39 dd 5f 03 da 8b 03 c1 c0 0f 83 e0 13 03 c8 4f 89 0e ba 00 00 00 10 c1 c2 06 03 f2 } //00 00 
	condition:
		any of ($a_*)
 
}