
rule Trojan_Win32_Zusy_NZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {a3 60 c6 40 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 94 b0 40 00 8b c3 e8 b1 e8 ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 cc 4c b3 0a 81 aa ?? ?? ?? ?? 45 a8 93 fb 0c 67 13 4b ?? 7e f3 ff b3 9f bb b9 b5 } //5
		$a_01_1 = {31 cf 44 e2 23 86 f3 69 7d e2 a0 3d 7f 43 04 02 45 e6 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win32_Zusy_NZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 6f fd ff ff 8b 4c 24 ?? 8b 54 24 08 85 c9 88 48 14 89 ?? ?? ?? ?? ?? 75 09 6a fd ff 15 2c 32 } //5
		$a_01_1 = {70 00 72 00 6f 00 2e 00 70 00 61 00 72 00 74 00 72 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 } //1 pro.partria.com
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Zusy_NZ_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 3f 23 75 f2 8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 50 5f 00 } //3
		$a_01_1 = {83 c7 04 83 e9 04 77 f1 01 cf e9 2c ff ff ff 5e 89 f7 b9 d0 ac 00 00 8a 07 47 2c e8 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Zusy_NZ_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 41 08 c7 41 04 00 00 00 00 89 51 0c 8b 06 89 41 10 8b 45 f8 89 0e ff 00 ff 75 fc ff d3 8b 77 50 6a 20 } //3
		$a_01_1 = {47 65 74 4e 61 74 69 76 65 53 79 73 74 65 6d 49 6e 66 6f } //1 GetNativeSystemInfo
		$a_01_2 = {57 53 41 53 65 6e 64 } //1 WSASend
		$a_01_3 = {3a 4a 3a 4f 3a 58 3a 56 3a 53 3a 59 3a } //1 :J:O:X:V:S:Y:
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule Trojan_Win32_Zusy_NZ_MTB_6{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6e 74 69 61 6e 61 6c 79 73 69 65 72 20 73 74 61 72 74 65 64 } //2 antianalysier started
		$a_01_1 = {65 6e 63 6f 64 65 64 50 61 79 6c 6f 61 64 5f 70 61 73 73 77 6f 72 64 } //1 encodedPayload_password
		$a_01_2 = {28 20 69 20 64 6f 6e 74 20 6c 6f 76 65 20 75 2c 20 62 72 6f 28 28 28 } //1 ( i dont love u, bro(((
		$a_01_3 = {40 20 77 68 79 20 75 20 72 65 76 65 72 73 65 20 6d 79 20 73 74 75 62 3f 28 28 } //1 @ why u reverse my stub?((
		$a_01_4 = {50 4f 6e 50 61 50 69 63 } //1 POnPaPic
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}