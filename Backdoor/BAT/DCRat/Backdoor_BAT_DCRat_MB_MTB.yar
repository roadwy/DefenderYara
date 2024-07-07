
rule Backdoor_BAT_DCRat_MB_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 ff a3 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 24 01 00 00 af 03 00 00 0e 0c 00 00 fd 1b 00 00 68 0b } //1
		$a_01_1 = {63 79 30 30 66 59 69 4a 49 41 6a 4c 6b 6d 31 54 54 70 } //1 cy00fYiJIAjLkm1TTp
		$a_01_2 = {51 4e 43 72 73 69 4a 70 69 79 4e 79 62 4f 6a 79 56 33 2e 50 68 35 4f 6a 66 5a 54 75 64 38 32 30 5a 6b 48 61 6c } //1 QNCrsiJpiyNybOjyV3.Ph5OjfZTud820ZkHal
		$a_01_3 = {57 30 6d 36 53 6c 51 51 76 78 6e 39 31 48 32 75 67 66 } //1 W0m6SlQQvxn91H2ugf
		$a_01_4 = {58 6b 65 34 48 72 31 62 36 64 70 71 51 6c 6c 6a 46 70 } //1 Xke4Hr1b6dpqQlljFp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}