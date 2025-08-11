
rule Trojan_Linux_CobaltStrike_H_MTB{
	meta:
		description = "Trojan:Linux/CobaltStrike.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {be 30 fd 99 00 55 48 81 ee 30 fd 99 00 48 89 e5 48 c1 fe 03 48 89 f0 48 c1 e8 3f 48 01 c6 48 d1 fe 74 15 b8 00 00 00 00 48 85 c0 74 0b 5d bf 30 fd 99 00 ff e0 } //1
		$a_01_1 = {44 88 cb f6 c3 01 0f 94 47 f0 41 83 ea 0a 0f 9c 42 f0 8a 5f f0 44 8a 72 f0 44 20 f3 44 8a 77 f0 44 8a 7a f0 45 30 fe 44 08 f3 80 e3 01 88 58 f0 48 89 e0 48 83 c0 f0 48 89 c4 c7 00 ee 5d 15 26 48 83 ec 0a 50 68 93 45 41 1d 31 c0 0f 84 01 00 00 00 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}