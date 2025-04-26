
rule Trojan_Win64_Rhadamanthys_A_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 28 44 24 20 0f 28 4c 24 30 0f 29 4c 24 50 0f 29 44 24 40 48 8b 05 2b 46 11 00 48 8b 00 48 85 c0 ?? ?? 25 00 40 00 00 31 c9 48 09 c8 ?? ?? ?? ?? ?? ?? 4c 8d [0-10] 41 b9 08 00 00 00 } //2
		$a_03_1 = {48 c7 44 24 20 0c 00 00 00 41 b8 1b 00 00 00 48 8d 7c 24 50 48 89 f9 48 8d 15 71 8d 06 00 4c 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? 48 89 fa e8 ?? ?? ?? ?? 31 c0 48 3b 44 24 30 0f 81 ?? ?? ?? ?? 4c 8b 6c 24 38 48 8b 7c 24 40 31 c9 31 d2 4d 89 e8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}