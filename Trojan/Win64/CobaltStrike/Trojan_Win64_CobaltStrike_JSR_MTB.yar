
rule Trojan_Win64_CobaltStrike_JSR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f be 0a 8b 11 44 0f be c2 41 8b d1 41 33 d0 41 88 12 49 ff c2 49 83 eb 01 75 e4 } //1
		$a_01_1 = {63 6f 62 61 6c 74 2d 73 74 72 69 6b 65 2d 6d 61 73 74 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6d 73 65 64 67 65 2e 70 64 62 } //1 cobalt-strike-master\x64\Release\msedge.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}