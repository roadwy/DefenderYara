
rule Trojan_Win32_Lokibot_GJ_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.GJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 b0 1f 00 00 55 8b ec 81 ec e0 00 00 00 56 57 b8 6b 00 00 00 66 89 45 dc b9 65 00 00 00 66 89 4d de ba 72 00 00 00 66 89 55 e0 b8 6e 00 00 00 66 89 45 e2 b9 65 00 00 00 66 89 4d e4 ba 6c 00 00 00 66 89 55 e6 b8 33 00 00 00 66 89 45 e8 b9 32 00 00 00 66 89 4d ea ba 2e 00 00 00 66 89 55 ec b8 64 00 00 00 66 89 45 ee b9 6c 00 00 00 66 89 4d f0 ba 6c 00 00 00 66 89 55 f2 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}