
rule Trojan_Win32_Zbot_CM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 1e 0f b6 c8 32 d8 83 e1 07 d2 cb 88 1e 8b 5c 24 18 80 c2 01 83 c6 01 83 ef 01 75 b3 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}