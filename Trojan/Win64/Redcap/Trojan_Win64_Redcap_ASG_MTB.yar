
rule Trojan_Win64_Redcap_ASG_MTB{
	meta:
		description = "Trojan:Win64/Redcap.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 f7 f1 48 8b c2 48 8b 8c 24 f8 00 00 00 0f b6 04 01 48 8b 4c 24 28 48 8b 94 24 00 01 00 00 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 28 48 8b 54 24 38 48 03 d1 48 8b ca 88 01 eb } //2
		$a_01_1 = {48 89 44 24 48 48 8b 44 24 30 8b 40 50 41 b9 40 00 00 00 41 b8 00 30 00 00 8b d0 33 c9 ff 54 24 48 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}