
rule Trojan_Win64_IcedID_EA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 54 24 10 48 89 4c 24 08 eb d7 80 44 24 4b 28 c6 44 24 4c 4e eb 00 80 44 24 4c 26 c6 44 24 4d 62 eb 18 44 89 4c 24 20 4c 89 44 24 18 eb d0 80 44 24 4a 07 c6 44 24 4b 4a eb d0 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win64_IcedID_EA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 4c 24 20 4c 89 44 24 18 eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win64_IcedID_EA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 eb 59 80 44 24 42 24 c6 44 24 43 4d eb dc 48 81 ec 88 08 00 00 c6 44 24 40 76 eb 0c 80 44 24 45 43 c6 44 24 46 0d eb 0c 80 44 24 40 00 c6 44 24 41 5b eb 1b } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win64_IcedID_EA_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 62 6b 73 61 6a 6e 61 68 62 73 66 6a 61 6b 73 66 6e 68 62 61 6b 73 66 } //10 hbksajnahbsfjaksfnhbaksf
		$a_01_1 = {75 72 68 6a 62 74 6e 65 6b 73 75 62 61 73 68 64 61 6a 6b 73 64 61 73 } //10 urhjbtneksubashdajksdas
		$a_01_2 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}
rule Trojan_Win64_IcedID_EA_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 69 62 68 61 73 6e 64 75 79 62 61 73 6f 64 6d 6a 6e 75 68 79 61 73 64 6a 61 73 61 } //5 yibhasnduybasodmjnuhyasdjasa
		$a_01_1 = {75 61 73 69 66 62 79 75 67 61 73 68 66 6a 61 6b 73 68 62 61 73 73 } //5 uasifbyugashfjakshbass
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_3 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //1 CreateEventW
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Trojan_Win64_IcedID_EA_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {79 61 75 73 67 62 66 61 74 73 64 75 68 61 73 64 61 6a 64 68 61 79 73 75 64 6a 61 73 } //5 yausgbfatsduhasdajdhaysudjas
		$a_01_1 = {61 6a 69 6f 73 64 75 61 68 79 67 73 64 61 68 69 69 73 6b 61 73 } //5 ajiosduahygsdahiiskas
		$a_01_2 = {75 61 73 69 66 62 79 75 67 61 73 68 66 6a 61 6b 73 68 62 61 73 73 } //5 uasifbyugashfjakshbass
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_4 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //1 CreateEventW
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}