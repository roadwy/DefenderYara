
rule Trojan_Win32_Zbot_DT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {87 ca 33 ce 4a 41 8b d3 81 e2 3b cc ac 85 8b ce 8d 15 f4 0c 00 00 4a 21 f9 32 c4 2b dd c1 e9 16 41 8d 0d b4 09 00 00 03 d6 3a d8 73 02 1b cf 87 ca 8b da c1 eb 0f b9 00 00 00 00 0f bd d1 74 02 } //01 00 
		$a_01_1 = {03 d6 4a 81 e3 7a f4 f2 79 81 e3 89 85 81 d3 81 e2 3f 56 2e 37 42 3a cd 76 02 87 d9 0f ba e1 02 72 02 1b d7 b9 00 00 00 00 87 d9 0f bd d1 74 04 } //00 00 
	condition:
		any of ($a_*)
 
}