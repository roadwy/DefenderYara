
rule Trojan_Win64_MalWmiExec_A_MTB{
	meta:
		description = "Trojan:Win64/MalWmiExec.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 8b e0 89 5c 24 70 48 8d 7d e0 41 bd 01 00 00 00 } //1
		$a_00_1 = {4a 8b 4c e1 28 4c 8d 4c 24 30 41 b8 00 10 00 00 48 89 7c 24 20 48 8d 54 24 40 } //1
		$a_02_2 = {8b 54 24 30 33 c9 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d 44 24 30 48 89 44 24 20 44 8b 4c 24 30 4c 8b c7 ba 19 00 00 00 48 8b 4c 24 38 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}