
rule Trojan_Win32_Trickbot_RL_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {31 d7 89 fa 88 16 41 81 e1 90 01 04 8b 7c 88 90 01 01 8b 14 24 01 fa 81 e2 90 01 04 89 14 24 8b 6c 90 01 02 89 6c 88 90 01 01 89 7c 90 01 02 01 ef 81 e7 90 01 04 8b 7c b8 90 01 01 8a 90 01 02 31 d7 89 fa 88 90 00 } //02 00 
		$a_02_1 = {31 c8 89 d1 c1 e1 90 01 01 c1 f9 90 01 01 81 e1 90 01 04 31 c8 c1 e2 90 01 01 c1 fa 90 01 01 81 e2 90 01 04 31 d0 0f b6 53 90 01 01 43 85 d2 0f 85 90 01 04 f7 d0 5b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}