
rule Trojan_Win64_Mikey_AH_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c7 32 04 29 88 01 48 8d 49 ?? 48 83 ea ?? 75 } //30
		$a_01_1 = {f3 0f 6f 4c 01 e0 f3 0f 7f 40 d0 0f 57 ce f3 0f 7f 48 e0 48 3b f2 72 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}
rule Trojan_Win64_Mikey_AH_MTB_2{
	meta:
		description = "Trojan:Win64/Mikey.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 c6 32 04 0b 88 04 0e 45 02 f7 48 ff c1 48 3b cf 72 } //30
		$a_03_1 = {0f b6 02 8b c8 c1 e9 ?? c0 e0 ?? 0a c8 88 0a 48 8d 52 ?? 48 83 ef ?? 75 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}
rule Trojan_Win64_Mikey_AH_MTB_3{
	meta:
		description = "Trojan:Win64/Mikey.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 0f be 00 83 f0 ?? 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 eb } //30
		$a_03_1 = {48 8d 84 04 48 1f 00 00 b9 ?? 00 00 00 48 6b c9 ?? c6 04 08 ?? b8 ?? 00 00 00 48 6b c0 ?? 48 8d 84 04 48 1f 00 00 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}