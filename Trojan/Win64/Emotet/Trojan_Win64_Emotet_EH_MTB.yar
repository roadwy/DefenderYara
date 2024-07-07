
rule Trojan_Win64_Emotet_EH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 02 43 32 14 0b 41 88 11 49 ff c1 48 83 ef 01 75 c6 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win64_Emotet_EH_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 8d 04 0a 48 03 c8 48 8d 04 49 49 8b cb 49 ff c3 48 2b c8 44 88 04 39 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EH_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 76 01 f7 e7 8b cf ff c7 c1 ea 04 6b c2 34 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 36 ff 88 46 ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win64_Emotet_EH_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 2c 00 00 00 f7 f9 48 63 ca 48 8b 05 90 01 04 0f b6 04 08 8b d7 33 d0 48 63 8c 24 90 01 04 48 8b 05 90 01 04 88 14 08 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EH_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 48 c7 44 24 58 fe 60 00 00 83 fa 64 0f 85 a4 00 00 00 c7 44 24 34 64 d5 00 00 4c 89 44 24 20 c1 6c 24 34 06 81 74 24 34 75 f9 0f 00 c7 44 24 30 1e ae 00 00 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}