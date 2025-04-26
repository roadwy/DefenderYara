
rule Trojan_Win64_PasswordStealer_AMQ_MTB{
	meta:
		description = "Trojan:Win64/PasswordStealer.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 63 d0 4c 63 c0 4e 0f b6 04 01 41 80 f0 ab 44 88 84 14 af 01 00 00 83 c0 01 83 f8 0c 75 e1 } //10
		$a_80_1 = {61 61 61 65 25 61 65 25 61 61 65 25 63 43 47 25 27 43 43 52 57 61 61 65 25 25 61 61 74 35 61 70 35 25 63 43 } //aaae%ae%aae%cCG%'CCRWaae%%aat5ap5%cC  3
		$a_80_2 = {64 72 69 76 65 72 73 5c 75 69 5c 4e 76 53 6d 61 72 74 4d 61 78 5c 4e 76 53 6d 61 72 74 4d 61 78 41 70 70 } //drivers\ui\NvSmartMax\NvSmartMaxApp  3
		$a_80_3 = {52 75 25 63 56 35 25 61 74 34 72 52 53 65 27 34 34 37 43 47 70 74 35 61 61 74 35 61 61 76 } //Ru%cV5%at4rRSe'447CGpt5aat5aav  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}