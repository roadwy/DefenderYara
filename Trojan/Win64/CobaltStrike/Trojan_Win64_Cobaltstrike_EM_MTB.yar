
rule Trojan_Win64_Cobaltstrike_EM_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 53 5f b0 c6 fc ae 75 fd 57 59 53 5e 8a 06 30 07 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Cobaltstrike_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 1e ff 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca 7b 03 00 00 44 2b c1 41 fe c0 41 32 c0 40 32 c5 88 43 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_EM_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 63 cb 31 d2 4c 89 e1 ff 15 90 01 04 49 89 c0 31 c0 48 89 c2 83 e2 07 8a 14 17 32 14 06 41 88 14 00 48 ff c0 39 c3 7f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_EM_MTB_4{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 65 74 6b 65 65 65 6d 79 73 65 63 } //1 Petkeeemysec
		$a_01_1 = {74 6b 63 65 65 6d 79 73 65 63 72 65 74 6b 65 65 65 6d 79 73 65 63 72 65 74 6b 65 65 65 6d 79 73 65 63 72 65 74 6b } //1 tkceemysecretkeeemysecretkeeemysecretk
		$a_01_2 = {79 73 65 63 72 65 74 6b 65 65 65 6d 79 70 65 } //1 ysecretkeeemype
		$a_01_3 = {74 65 74 6b 65 65 65 6d 79 73 65 63 72 65 74 6b 65 65 65 6d 79 73 65 63 72 65 74 45 } //1 tetkeeemysecretkeeemysecretE
		$a_01_4 = {5c 6b 61 70 6c 79 61 2e 70 64 62 } //1 \kaplya.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}