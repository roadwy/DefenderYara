
rule Trojan_Win64_BumbleBee_BN_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 63 71 61 37 35 } //1 Ocqa75
		$a_01_1 = {51 45 70 7a 4b 62 36 } //1 QEpzKb6
		$a_01_2 = {55 7a 64 75 55 4f 74 52 5a 42 } //1 UzduUOtRZB
		$a_01_3 = {43 61 6c 6c 4e 61 6d 65 64 50 69 70 65 41 } //1 CallNamedPipeA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_BumbleBee_BN_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 69 59 57 39 33 39 35 46 } //1 IiYW9395F
		$a_01_1 = {4f 69 67 66 78 30 77 38 } //1 Oigfx0w8
		$a_01_2 = {55 48 70 77 6a 75 33 33 34 36 4e 56 } //1 UHpwju3346NV
		$a_01_3 = {50 6a 79 4a 47 47 43 76 51 73 } //1 PjyJGGCvQs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}