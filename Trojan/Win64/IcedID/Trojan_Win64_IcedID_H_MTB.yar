
rule Trojan_Win64_IcedID_H_MTB{
	meta:
		description = "Trojan:Win64/IcedID.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 ff c0 66 3b ff 74 4c 88 08 48 8b 04 24 66 3b d2 74 1a 48 8b 44 24 20 48 89 04 24 66 3b c0 74 3f 48 8b 4c 24 08 8a 09 66 3b ff 74 db } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win64_IcedID_H_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 38 66 3b d2 74 1d 44 89 4c 24 20 4c 89 44 24 18 3a f6 74 00 48 89 54 24 10 48 89 4c 24 08 66 3b f6 74 20 } //2
		$a_01_1 = {66 61 68 67 64 61 67 79 75 73 64 61 6a 73 64 6b 61 73 } //1 fahgdagyusdajsdkas
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_IcedID_H_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 5d 00 00 00 83 c0 08 66 3b ed 74 ba 83 c0 29 66 89 44 24 52 66 3b c0 74 00 33 c0 66 89 44 24 54 66 3b f6 74 43 b8 05 00 00 00 83 c0 2e 66 3b d2 74 27 } //2
		$a_01_1 = {79 67 61 73 62 64 6a 6b 62 73 79 64 75 6a 68 61 6b 73 64 61 73 64 73 } //1 ygasbdjkbsydujhaksdasds
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}