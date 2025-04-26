
rule Trojan_Win32_DistTrack_A{
	meta:
		description = "Trojan:Win32/DistTrack.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8b f0 33 c9 8d 46 01 ba 02 00 00 00 f7 e2 0f 90 c1 f7 d9 0b c8 51 e8 f1 a2 00 00 33 c9 83 c4 04 66 89 0c 70 85 f6 74 16 8b d7 8b c8 2b d0 } //1
		$a_03_1 = {e8 d3 e6 ff ff bb 11 00 00 00 b8 ?? ?? ?? ?? e8 e4 be ff ff 8d 4c 24 20 51 89 44 24 24 c7 44 24 28 ?? ?? ?? ?? 89 7c 24 2c 89 7c 24 30 ff 15 ?? ?? ?? ?? 85 c0 75 36 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}