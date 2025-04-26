
rule Trojan_Win32_SystemBC_psyG_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 02 00 00 a1 24 7c 43 00 33 c4 89 84 24 08 56 33 c0 68 00 00 f0 58 06 50 8d 4c 24 0e 51 66 89 44 24 10 e8 8a 01 6c 4b 83 c4 0c c0 5c b8 16 68 04 01 8d 54 52 6a 00 40 77 98 05 ff 15 1c b2 42 04 6a 5c 50 e0 2e 20 b8 47 c3 8b f0 33 c9 0e 83 9e c5 a2 05 c6 02 6a 2e 56 33 d2 16 00 70 2f 10 10 8b d7 8b c6 2b d6 5e 8b ff 0f b7 08 04 00 79 89 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}