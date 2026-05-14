
rule Trojan_Win64_Vidar_KK_MTB{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 21 06 00 eb 54 00 00 18 55 00 00 68 21 06 00 } //20
		$a_01_1 = {21 57 00 00 90 21 06 00 21 57 00 00 33 57 00 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Vidar_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 84 24 90 00 00 00 48 83 c0 14 4c 8b 94 24 a8 00 00 00 44 8b 8c 24 8c 00 00 00 4c 89 c2 4d 89 d0 66 90 } //20
		$a_01_1 = {48 8d 3c 03 4c 8d 04 33 45 0f b6 00 44 88 07 48 ff c3 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Vidar_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 34 03 48 8b bc 24 98 00 00 00 48 01 df 0f b6 3f 40 88 3e 48 ff c3 } //20
		$a_03_1 = {48 8b 54 24 ?? 44 0f b6 4c 24 47 49 89 d8 48 89 cb 48 89 c1 48 8b 84 24 90 90 00 00 00 } //15
		$a_01_2 = {49 8d 40 01 48 8b b4 24 30 01 00 00 48 8b 8c 24 38 02 00 00 48 89 f2 48 8b bc 24 40 02 00 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*15+(#a_01_2  & 1)*10) >=45
 
}
rule Trojan_Win64_Vidar_KK_MTB_4{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8d 1c 02 48 8b b4 24 ?? 00 00 00 48 01 d6 0f b6 36 40 88 33 48 ff c2 } //20
		$a_03_1 = {8b 71 04 48 8b 7c 24 ?? 48 8d 1c 37 48 8b 84 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 48 8b 54 24 } //10
		$a_01_2 = {6d 61 69 6e 2e 47 65 74 49 6e 73 74 61 6c 6c 44 65 74 61 69 6c 73 50 61 79 6c 6f 61 64 } //5 main.GetInstallDetailsPayload
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win64_Vidar_KK_MTB_5{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 4c 3c 50 89 ca c1 ea 04 0f b6 14 02 42 88 14 7e 83 e1 0f 0f b6 0c 01 42 88 4c 7e 01 42 0f b6 4c 3c 51 89 ca c1 ea 04 0f b6 14 02 42 88 54 7e 02 83 e1 0f 0f b6 0c 01 42 88 4c 7e 03 49 83 c7 02 4c 39 ff 75 b8 } //20
		$a_01_1 = {61 33 62 36 34 66 37 63 61 31 65 66 36 35 38 38 36 30 37 65 61 63 34 61 64 64 39 37 66 64 35 64 66 62 62 39 36 33 39 31 37 35 64 34 30 31 32 30 33 38 66 63 35 30 39 38 34 63 30 33 35 62 63 64 } //5 a3b64f7ca1ef6588607eac4add97fd5dfbb9639175d4012038fc50984c035bcd
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5) >=25
 
}