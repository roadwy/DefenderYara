
rule Trojan_Win64_Zusy_SXG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 63 47 3c 48 8b 4c 24 58 48 03 c3 4c 89 64 24 20 44 8b 84 38 ?? ?? ?? ?? 8b 94 38 ?? ?? ?? ?? 4c 03 c7 44 8b 8c 38 ?? ?? ?? ?? 49 03 d6 41 ff d7 0f b7 45 06 ff c6 48 83 c3 28 3b f0 7c } //5
		$a_03_1 = {48 89 5c 24 20 41 ff d7 8b 45 28 48 8d 54 24 ?? 48 8b 4c 24 ?? 49 03 c6 48 89 84 24 ?? ?? ?? ?? 41 ff d5 48 8b 4c 24 ?? ff 54 24 } //3
		$a_01_2 = {f3 0f 7f 45 af 66 44 89 6d 9f 48 8d 55 e7 4c 8b 55 e7 4c 8b 5d ff 49 83 fb 10 49 0f 43 d2 48 c7 c3 ff ff ff ff 4c 8b 4d f7 4d 85 c9 74 2f } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}