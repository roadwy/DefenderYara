
rule Trojan_Win32_Trickbot_FC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6f 70 65 72 4e 6f 74 65 57 } //01 00 
		$a_01_1 = {89 7d e4 81 ef 4e c9 ea 32 83 ef 01 81 c7 4e c9 ea 32 89 45 e0 8b 45 e4 0f af c7 83 e0 01 83 f8 00 0f 94 c0 24 01 88 45 ee 83 fb 0a 0f 9c c0 24 01 88 45 ef c7 45 e8 7f a3 d9 4d } //01 00 
		$a_01_2 = {89 c2 81 c2 e2 47 3e 9e 83 ea 01 81 ea e2 47 3e 9e 0f af c2 83 e0 01 83 f8 00 0f 94 c0 83 f9 0a 0f 9c c4 88 c1 20 e1 30 e0 08 c1 f6 c1 01 ba 3c 3b fb 29 be 0b 74 9a 3c } //00 00 
	condition:
		any of ($a_*)
 
}