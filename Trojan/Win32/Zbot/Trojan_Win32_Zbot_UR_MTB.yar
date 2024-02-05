
rule Trojan_Win32_Zbot_UR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 04 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 90 01 01 75 05 31 c9 83 ea 90 01 01 47 39 f8 75 e8 90 00 } //0a 00 
		$a_01_1 = {56 57 33 ff 39 7c 24 0c 76 15 8b f1 2b f0 8a 0c 06 8a 10 3a ca 75 0f 47 40 3b 7c 24 0c 72 ef 33 c0 5f 5e c2 04 00 0f b6 d2 0f b6 c1 2b c2 eb f1 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}