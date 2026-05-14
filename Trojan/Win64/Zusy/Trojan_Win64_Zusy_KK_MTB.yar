
rule Trojan_Win64_Zusy_KK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 30 01 45 30 51 01 45 30 41 02 41 30 51 03 49 83 c1 04 83 e9 } //20
		$a_01_1 = {8a 44 0c 50 48 ff c1 41 30 01 49 ff c1 48 3b ca } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Zusy_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 44 0f b6 00 48 8b 45 28 0f b6 08 48 8b 55 18 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}
rule Trojan_Win64_Zusy_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 9c 01 00 00 48 98 0f b6 84 05 2a 01 00 00 84 c0 } //20
		$a_01_1 = {8b 85 9c 01 00 00 48 98 0f b6 84 05 2a 01 00 00 66 0f be d0 8b 85 9c 01 00 00 48 98 66 89 94 45 e0 00 00 00 83 85 9c 01 00 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Zusy_KK_MTB_4{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 43 0f 6f 04 08 0f 57 c2 f3 43 0f 7f 04 08 41 8d 42 f0 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 8b c2 f3 42 0f 6f 04 08 0f 57 c2 f3 42 0f 7f 04 08 41 8d 42 10 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 83 c0 40 41 83 c2 40 45 3b c3 } //6
		$a_01_1 = {41 8d 4a 01 45 8b ca 44 0f b6 04 19 42 0f b6 0c 13 41 80 e8 41 fe c9 49 d1 e9 c0 e1 04 41 83 c2 02 44 0a c1 45 88 04 01 8b 0f 44 3b d1 72 d1 } //10
		$a_01_2 = {54 75 6f 6e 69 41 67 65 6e 74 2e 64 6c 6c } //4 TuoniAgent.dll
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*10+(#a_01_2  & 1)*4) >=20
 
}
rule Trojan_Win64_Zusy_KK_MTB_5{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 6f 72 5f 64 61 74 61 2e 64 61 74 } //10 xor_data.dat
		$a_01_1 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5f 32 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 6d 75 6c 74 69 5f 78 6f 72 5f } //4 bypass\bypass-agent_2\workspace\ssvagent_multi_xor_
		$a_01_2 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5f 32 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 6d 6f 64 75 6c 65 5f 6f 76 65 72 6c 6f 61 64 5f 78 6f 72 5f } //4 bypass\bypass-agent_2\workspace\ssvagent_module_overload_xor_
		$a_01_3 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 6d 75 6c 74 69 5f 78 6f 72 } //4 bypass\bypass-agent\workspace\ssvagent_multi_xor
		$a_01_4 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 63 6c 61 73 73 69 63 5f 78 6f 72 5f } //4 bypass\bypass-agent\workspace\ssvagent_classic_xor_
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=14
 
}