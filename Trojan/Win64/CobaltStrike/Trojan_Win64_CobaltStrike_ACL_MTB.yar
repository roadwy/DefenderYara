
rule Trojan_Win64_CobaltStrike_ACL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 4c 24 38 ba ?? ?? ?? ?? 48 89 c1 41 b8 ?? ?? ?? ?? ff 16 89 c1 e8 ?? ?? ?? ?? 44 8a 63 58 41 83 f4 01 41 20 c4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ACL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 0f b7 00 66 89 45 f6 0f b7 45 f6 8b 55 f8 c1 ca 08 01 d0 31 45 f8 8b 45 fc 48 8b 55 10 48 01 d0 0f b6 00 84 c0 } //1
		$a_01_1 = {c6 45 c0 41 c6 45 c1 6f c6 45 c2 66 c6 45 c3 6e c6 45 c4 49 c6 45 c5 72 c6 45 c6 61 c6 45 c7 64 c6 45 c8 6e c6 45 c9 65 c6 45 ca 6c c6 45 cb 61 c6 45 cc 43 c6 45 cd 6d c6 45 ce 75 c6 45 cf 6e c6 45 d0 45 } //1
		$a_01_2 = {c6 85 45 1f 00 00 74 c6 85 46 1f 00 00 63 c6 85 47 1f 00 00 65 c6 85 48 1f 00 00 74 c6 85 49 1f 00 00 6f c6 85 4a 1f 00 00 72 c6 85 4b 1f 00 00 50 c6 85 4c 1f 00 00 6c c6 85 4d 1f 00 00 61 c6 85 4e 1f 00 00 75 c6 85 4f 1f 00 00 74 c6 85 50 1f 00 00 72 c6 85 51 1f 00 00 69 c6 85 52 1f 00 00 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}