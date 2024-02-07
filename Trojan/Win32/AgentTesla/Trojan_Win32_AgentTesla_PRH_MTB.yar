
rule Trojan_Win32_AgentTesla_PRH_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.PRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 e8 73 47 8b 4d ec 03 4d f4 8a 11 88 55 ff 8b 45 cc 03 45 e4 8a 08 88 4d fc 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fc 33 d1 8b 45 ec 03 45 f4 88 10 8b 45 e4 83 c0 01 99 b9 90 01 04 f7 f9 89 55 e4 eb a8 90 00 } //01 00 
		$a_01_1 = {4a 4b 62 74 67 64 66 64 } //01 00  JKbtgdfd
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //01 00  GetTempPathA
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}