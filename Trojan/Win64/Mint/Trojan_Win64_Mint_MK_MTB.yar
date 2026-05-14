
rule Trojan_Win64_Mint_MK_MTB{
	meta:
		description = "Trojan:Win64/Mint.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 0f b6 0a 84 c9 ?? ?? 48 ff c2 0f 1f 00 88 08 48 ff c0 0f b6 0a 48 ff c2 } //20
		$a_01_1 = {48 89 c8 48 89 d1 48 89 74 24 f8 48 89 7c 24 f0 4d 89 c2 4c 89 ca 4c 8b 44 24 28 4c 8b 4c 24 30 48 83 e9 04 } //10
		$a_01_2 = {52 45 4d 55 53 20 4c 4f 47 } //5 REMUS LOG
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}