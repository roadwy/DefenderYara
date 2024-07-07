
rule Trojan_Win32_AgentTesla_PRJ_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.PRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d e8 73 4d 8b 55 dc 03 55 f8 8a 02 88 45 db 8b 4d f0 03 4d e4 8a 11 88 95 c7 fe ff ff 0f b6 45 db c1 f8 03 0f b6 4d db c1 e1 05 0b c1 0f b6 95 c7 fe ff ff 33 c2 8b 4d dc 03 4d f8 88 01 8b 45 e4 83 c0 01 99 b9 0c 00 00 00 f7 f9 89 55 e4 eb a2 } //1
		$a_01_1 = {4a 4b 62 74 67 64 66 64 } //1 JKbtgdfd
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //1 GetTempPathA
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}