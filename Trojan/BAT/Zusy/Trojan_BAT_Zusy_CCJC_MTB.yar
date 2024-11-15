
rule Trojan_BAT_Zusy_CCJC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 66 65 63 74 41 44 } //5 InfectAD
		$a_81_1 = {49 6e 66 65 63 74 4f 75 74 6c 6f 6f 6b } //5 InfectOutlook
		$a_01_2 = {59 6f 75 20 63 61 6e 20 6b 69 6c 6c 20 61 20 70 65 6f 70 6c 65 2c 20 62 75 74 20 79 6f 75 20 63 61 6e 27 74 20 6b 69 6c 6c 20 61 6e 20 69 64 65 61 2e 20 52 65 73 69 73 74 61 6e 63 65 20 77 69 6c 6c 20 63 6f 6e 74 69 6e 75 65 20 75 6e 74 69 6c 20 74 68 65 20 66 69 6e 61 6c 20 6c 69 62 65 72 61 74 69 6f 6e 20 6f 66 20 61 6c 6c 20 50 61 6c 65 73 74 69 6e 69 61 6e 20 6c 61 6e 64 73 2c 20 61 6e 64 20 69 74 20 69 73 20 6f 6e 6c 79 20 61 20 6d 61 74 74 65 72 20 6f 66 20 74 69 6d 65 2e } //1 You can kill a people, but you can't kill an idea. Resistance will continue until the final liberation of all Palestinian lands, and it is only a matter of time.
		$a_81_3 = {4b 47 39 69 61 6d 56 6a 64 45 4e 73 59 58 4e 7a 50 57 4e 76 62 58 42 31 64 47 56 79 4b 51 3d 3d } //1 KG9iamVjdENsYXNzPWNvbXB1dGVyKQ==
		$a_81_4 = {54 57 6c 6a 63 6d 39 7a 62 32 5a 30 52 57 52 6e 5a 56 56 77 5a 47 46 30 5a 56 52 68 63 32 74 4e 59 57 4e 6f 61 57 35 6c 63 31 56 42 } //1 TWljcm9zb2Z0RWRnZVVwZGF0ZVRhc2tNYWNoaW5lc1VB
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*5+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=13
 
}