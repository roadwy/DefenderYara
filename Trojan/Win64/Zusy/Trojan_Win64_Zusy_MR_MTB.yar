
rule Trojan_Win64_Zusy_MR_MTB{
	meta:
		description = "Trojan:Win64/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 01 48 8d 49 01 ff c0 3b c7 7c } //10
		$a_01_1 = {44 8b c0 b8 4f ec c4 4e 41 f7 e8 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 1a 44 2b c1 49 63 c0 0f b6 04 38 88 44 1c 30 48 ff c3 48 83 fb 08 } //30
		$a_01_2 = {45 79 65 4c 6f 76 65 4d 79 4d 75 74 65 58 } //10 EyeLoveMyMuteX
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*30+(#a_01_2  & 1)*10) >=50
 
}
rule Trojan_Win64_Zusy_MR_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 84 24 ad 01 00 00 d3 c6 84 24 ae 01 00 00 67 c6 84 24 af 01 00 00 5b c7 84 24 b0 01 00 00 cf be 3a 46 } //10
		$a_03_1 = {41 8b cb 41 8b c3 48 c1 e9 10 25 ff 00 04 00 83 e1 06 89 ?? ?? 72 05 00 48 81 c9 29 00 00 01 48 f7 d1 ?? ?? 0d 80 4f 05 00 48 ?? ?? 79 4f 05 00 3c 01 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}
rule Trojan_Win64_Zusy_MR_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 15 ac 1e 0d 00 8b c2 83 e0 3f 48 8b da 48 33 1d 85 49 0d 00 8b c8 48 d3 cb b9 40 00 00 00 2b c8 48 d3 cf 48 33 fa 48 89 3d 6c 49 0d 00 33 c9 } //5
		$a_01_1 = {4c 8b 15 cd 13 0d 00 41 8b ca 49 8b f2 48 33 32 83 e1 3f 4d 8b ca 48 d3 ce 4c 33 4a 08 49 8b da 48 33 5a 10 49 d3 c9 48 d3 cb 4c 3b cb } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*10) >=15
 
}