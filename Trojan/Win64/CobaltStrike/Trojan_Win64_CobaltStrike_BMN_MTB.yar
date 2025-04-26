
rule Trojan_Win64_CobaltStrike_BMN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 b9 ?? ?? ?? ?? e8 ?? ?? ff ff 4c 8b f8 b9 ?? ?? ?? ?? e8 ?? ?? ff ff 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 41 ff e7 } //1
		$a_03_1 = {89 05 8b 38 02 00 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 4c 8d [0-07] 45 33 c0 48 8d 15 15 39 02 00 48 c7 c1 ff ff ff ff e8 } //1
		$a_01_2 = {25 42 eb 96 f3 89 05 a8 3f 02 00 8b 05 a6 3f 02 00 05 7a 9f cc f4 89 05 97 3f 02 00 8b 05 91 3f 02 00 35 88 e8 83 a3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}