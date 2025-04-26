
rule Trojan_Win64_BumbleBee_BM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 6c 6f 4f 45 45 69 48 6a } //1 MloOEEiHj
		$a_01_1 = {50 76 68 67 4f 71 } //1 PvhgOq
		$a_01_2 = {4e 79 47 6c 69 73 44 49 4b 4e } //1 NyGlisDIKN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win64_BumbleBee_BM_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 57 59 37 32 } //1 EWY72
		$a_01_1 = {51 43 59 5a 6e 36 37 34 37 48 } //1 QCYZn6747H
		$a_01_2 = {51 4f 55 58 49 33 31 } //1 QOUXI31
		$a_01_3 = {52 6f 4f 45 69 7a 74 4a 76 57 } //1 RoOEiztJvW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_BumbleBee_BM_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 4c 41 49 33 } //1 FLAI3
		$a_01_1 = {47 48 6a 61 63 75 64 52 } //1 GHjacudR
		$a_01_2 = {47 78 42 6c 4f 4f } //1 GxBlOO
		$a_01_3 = {53 65 74 56 50 41 43 6f 6e } //5 SetVPACon
		$a_01_4 = {59 43 6c 68 6a 36 33 34 66 78 67 7a } //1 YClhj634fxgz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1) >=9
 
}