
rule Trojan_Win64_Winnti_A_dha{
	meta:
		description = "Trojan:Win64/Winnti.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {48 89 5c 24 08 48 89 7c 24 10 48 63 d9 48 8d ?? ?? ?? ?? ?? 44 8b d2 48 c1 e3 06 80 e2 0f 41 c1 ea 04 44 0f b6 c2 0f b6 ca 41 80 e2 0f c0 e1 03 45 0f b6 ca 41 8b c1 49 33 c0 49 d1 e8 48 03 c3 49 0b c8 44 0f b6 1c 38 83 e1 0f 41 0f b6 c2 c0 e0 03 45 8b c3 49 33 c1 83 e0 0f 48 33 c8 48 03 cb 0f b6 44 39 10 } //5
		$a_00_1 = {71 40 33 24 25 68 79 2a 26 75 } //5 q@3$%hy*&u
		$a_00_2 = {74 77 6f 66 69 73 68 } //1 twofish
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1) >=10
 
}