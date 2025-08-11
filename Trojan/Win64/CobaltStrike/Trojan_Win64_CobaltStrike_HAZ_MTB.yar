
rule Trojan_Win64_CobaltStrike_HAZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 c9 41 b9 40 00 00 00 41 b8 00 30 00 00 41 ff d6 48 8b f0 } //5
		$a_03_1 = {8b d0 ff c0 0f b6 0c 17 88 0c 16 41 3b 44 24 ?? 72 } //4
		$a_01_2 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
		$a_01_3 = {53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 3b } //1 SELECT host_key, name, encrypted_value FROM cookies;
		$a_01_4 = {63 68 72 6f 6d 65 5f 64 65 63 72 79 70 74 2e 6c 6f 67 } //1 chrome_decrypt.log
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}