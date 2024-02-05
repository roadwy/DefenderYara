
rule Trojan_Win32_Qbot_I_MSR{
	meta:
		description = "Trojan:Win32/Qbot.I!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 d0 89 74 24 38 8b 74 24 24 0f b6 3c 16 89 fb c7 44 24 3c 00 00 00 00 c7 44 24 38 ff 59 e1 5f 8b 74 24 10 01 fe 89 44 24 0c 89 f0 c1 f8 1f c1 e8 18 89 44 24 08 89 f0 89 4c 24 04 8b 4c 24 08 01 c8 25 00 ff ff ff 29 c6 8b 44 24 24 8a 3c 30 88 3c 10 88 1c 30 8b 4c 24 2c 8b 44 24 04 8a 1c 01 8b 44 24 24 0f b6 14 10 01 fa 88 d7 0f b6 d7 8a 3c 10 30 df 8b 54 24 44 66 8b 7c 24 22 66 89 7c 24 34 8b 44 24 38 35 98 59 f9 7b 81 c2 a5 67 da f0 89 44 24 38 8b 44 24 28 8b 4c 24 04 88 3c 08 01 d1 8b 54 24 30 39 d1 8b 44 24 0c 89 44 24 14 89 4c 24 18 89 74 24 1c 0f 84 01 ff ff ff e9 04 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}