
rule Trojan_Win64_Rozena_SPF_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 00 00 00 00 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 eb 9d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Rozena_SPF_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 4c 24 50 41 b8 ff 03 00 00 48 8d 55 f0 48 8b cf ff 15 90 01 04 44 8b 4c 24 50 4c 8d 45 f0 48 8b 54 24 60 48 8d 4c 24 58 e8 90 01 04 83 7c 24 50 00 75 90 00 } //1
		$a_03_1 = {48 8b 7c 24 60 48 8b 74 24 58 48 2b fe 41 b9 90 01 04 41 b8 90 01 04 48 8b d7 33 c9 ff 15 90 01 04 48 8b d8 4c 8b c7 48 8b d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}