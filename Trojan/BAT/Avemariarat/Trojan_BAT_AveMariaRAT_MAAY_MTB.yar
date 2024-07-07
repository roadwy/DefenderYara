
rule Trojan_BAT_AveMariaRAT_MAAY_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.MAAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 61 63 65 63 38 38 36 64 2d 38 39 61 38 2d 34 31 35 33 2d 39 37 30 36 2d 63 32 62 64 65 63 33 38 39 31 34 34 } //10 $acec886d-89a8-4153-9706-c2bdec389144
		$a_01_1 = {24 37 66 38 34 66 65 62 31 2d 64 30 32 62 2d 34 31 62 37 2d 61 39 35 31 2d 62 39 39 30 63 30 30 64 39 63 39 33 } //10 $7f84feb1-d02b-41b7-a951-b990c00d9c93
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 } //1 Confuser.Core 1.6
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}