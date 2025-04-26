
rule Trojan_Win64_CobaltStrike_PC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 33 db 41 ba 13 9d d9 35 48 8b c2 66 0f 1f 44 00 00 0f b7 00 41 8b ca c1 c9 08 41 ff c3 03 c8 41 8b c3 48 03 c2 44 33 d1 80 38 00 75 ?? 4a 8d 0c [0-06] 41 ff c0 46 89 54 39 ?? 0f b7 44 5d ?? 41 8b ?? 86 42 89 44 39 } //1
		$a_01_1 = {66 75 63 6b 20 73 61 6e 64 62 6f 78 } //1 fuck sandbox
		$a_01_2 = {5c 42 79 70 61 73 73 5f 41 56 2e 70 64 62 } //1 \Bypass_AV.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}