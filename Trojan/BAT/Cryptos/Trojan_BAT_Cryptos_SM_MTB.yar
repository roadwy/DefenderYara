
rule Trojan_BAT_Cryptos_SM_MTB{
	meta:
		description = "Trojan:BAT/Cryptos.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 6c 6e 68 77 6b 66 75 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Elnhwkfu.Properties.Resources.resources
		$a_81_1 = {24 36 32 32 35 61 33 61 36 2d 39 33 30 35 2d 34 31 36 65 2d 39 66 36 66 2d 61 30 33 32 34 66 31 35 64 36 65 66 } //1 $6225a3a6-9305-416e-9f6f-a0324f15d6ef
		$a_81_2 = {49 66 35 73 4c 68 52 6a 67 35 51 3d } //1 If5sLhRjg5Q=
		$a_81_3 = {68 68 6d 51 65 75 42 64 36 78 42 41 6e 43 30 5a 63 64 59 6a 68 41 3d 3d } //1 hhmQeuBd6xBAnC0ZcdYjhA==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}