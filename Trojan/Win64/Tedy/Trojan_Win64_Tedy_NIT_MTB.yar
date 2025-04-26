
rule Trojan_Win64_Tedy_NIT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 74 24 30 eb 0f 44 8b 63 10 4d 03 e6 49 8b f4 4c 89 64 24 30 4c 89 64 24 28 49 8b 04 24 48 85 c0 74 3a 48 b9 00 00 00 00 00 00 00 80 48 85 c1 49 8b cf 0f b7 d0 75 05 4a 8d 54 30 02 ff 15 ca 9e 17 00 48 89 06 48 85 c0 75 08 33 ff 89 7c 24 20 eb 0e 49 83 c4 08 48 83 c6 08 eb a2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}