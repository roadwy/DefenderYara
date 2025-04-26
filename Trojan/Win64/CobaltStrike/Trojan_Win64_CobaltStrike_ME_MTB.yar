
rule Trojan_Win64_CobaltStrike_ME_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d 29 99 0e 00 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 15 9d 0e 00 43 33 1c 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ME_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {f0 00 23 00 0b 02 0e 1d 00 bc 08 00 00 ?? 66 } //5
		$a_01_1 = {e3 68 ee be b8 2f bf b7 47 54 57 91 d1 a3 6c 7c 22 09 44 c7 3c cc 31 54 67 78 87 60 ab 43 39 7c 36 5f 22 ca 94 02 59 31 77 b1 b7 53 8c d6 f3 cd } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}
rule Trojan_Win64_CobaltStrike_ME_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 44 24 38 33 c9 48 8d 44 24 30 48 89 44 24 28 4c 8d 05 ?? ?? ?? ?? 45 33 c9 89 4c 24 20 33 d2 89 4c 24 30 ff 15 } //5
		$a_01_1 = {8b 7c 24 48 33 c9 8b d7 41 b8 00 30 00 00 44 8b ff 44 8d 49 04 ff 15 } //5
		$a_01_2 = {53 74 61 72 74 44 6c 6c 4c 6f 61 64 44 61 74 61 } //5 StartDllLoadData
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}