
rule Trojan_Win64_Convagent_SXD_MTB{
	meta:
		description = "Trojan:Win64/Convagent.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 83 fc 10 74 39 41 b8 10 00 00 00 4c 89 e1 48 89 ea 49 89 f9 e8 ?? ?? ?? ?? 48 83 fa 03 0f 86 ?? ?? ?? ?? 8b 00 49 83 fc 0c 89 c1 0f c9 0f 45 c8 42 89 8c 24 ?? ?? ?? ?? 49 83 c4 04 eb c1 } //20
		$a_03_1 = {48 29 c4 48 89 ce 4c 8d 8c 24 78 01 00 00 41 c7 01 30 75 00 00 c7 44 24 20 04 00 00 00 ba ff ff 00 00 41 b8 06 10 00 00 ff 15 ?? ?? ?? ?? 83 f8 ff 74 04 31 c9 eb 10 ff 15 ?? ?? ?? ?? 89 c1 48 c1 e1 20 48 83 c9 02 } //10
		$a_01_2 = {49 89 d1 48 8d 94 24 a0 07 00 00 b9 80 00 00 00 31 c0 48 89 d7 f3 ab 4c 8d 84 24 00 03 00 00 41 c7 00 00 01 00 00 b9 01 00 00 00 41 ff d1 85 c0 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}