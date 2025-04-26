
rule Trojan_Win64_IcedID_AW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 08 48 8b 04 24 3a ff 74 00 48 ff c0 48 89 04 24 66 3b e4 74 00 48 8b 44 24 08 48 ff c0 66 3b ff 74 9c 48 ff c8 48 89 44 24 30 e9 } //2
		$a_01_1 = {48 8b 4c 24 08 8a 09 66 3b db 74 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win64_IcedID_AW_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 89 c3 48 83 eb 05 b9 08 c1 44 00 48 29 cb 50 b8 d7 0d 2c 00 48 01 d8 83 38 00 74 03 } //10
		$a_81_1 = {73 61 64 6c 5f 36 34 2e 64 6c 6c } //3 sadl_64.dll
		$a_81_2 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //3 GetModuleHandleA
		$a_81_3 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //3 SHGetFolderPathA
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}
rule Trojan_Win64_IcedID_AW_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 47 69 65 57 72 51 36 6c 72 } //3 AGieWrQ6lr
		$a_01_1 = {41 6f 72 6c 4d 32 35 6c 75 } //3 AorlM25lu
		$a_01_2 = {41 79 50 59 4f 37 6c } //3 AyPYO7l
		$a_01_3 = {43 6f 47 65 74 53 74 64 4d 61 72 73 68 61 6c 45 78 } //3 CoGetStdMarshalEx
		$a_01_4 = {43 6f 49 6d 70 65 72 73 6f 6e 61 74 65 43 6c 69 65 6e 74 } //3 CoImpersonateClient
		$a_01_5 = {50 72 6f 70 56 61 72 69 61 6e 74 43 6f 70 79 } //3 PropVariantCopy
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}