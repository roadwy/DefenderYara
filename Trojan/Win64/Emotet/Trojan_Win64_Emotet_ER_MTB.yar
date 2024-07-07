
rule Trojan_Win64_Emotet_ER_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 0b ff 41 88 49 ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_ER_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 d0 89 ca 29 c2 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_ER_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 8b 4c 24 3c 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 50 88 04 0a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_ER_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_1 = {79 61 68 61 76 53 6f 64 75 6b 75 2e 74 78 74 } //1 yahavSoduku.txt
		$a_01_2 = {62 54 6c 5a 63 33 64 53 54 44 4a 50 52 7a 4a 6a 49 55 39 } //1 bTlZc3dSTDJPRzJjIU9
		$a_01_3 = {51 50 54 6f 49 6c } //1 QPToIl
		$a_01_4 = {51 6e 69 6d 51 73 43 42 6b 6e 69 79 } //1 QnimQsCBkniy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_Emotet_ER_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4a 6b 44 65 66 72 61 67 2e 64 6c 6c } //1 JkDefrag.dll
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {69 58 6a 63 74 65 6c 43 56 42 49 62 6c 52 61 7a 68 32 64 32 41 50 77 59 53 32 6a 32 4d 32 39 53 } //1 iXjctelCVBIblRazh2d2APwYS2j2M29S
		$a_01_3 = {58 43 61 6f 4e 56 68 61 56 65 74 64 33 46 78 39 69 31 6f 41 66 5a 33 6a 64 71 72 4c 30 63 77 61 71 74 52 41 58 74 4d 41 55 67 79 75 48 5a 77 65 72 73 54 53 43 6a 65 58 72 6d 52 76 41 34 } //1 XCaoNVhaVetd3Fx9i1oAfZ3jdqrL0cwaqtRAXtMAUgyuHZwersTSCjeXrmRvA4
		$a_01_4 = {48 65 61 70 52 65 41 6c 6c 6f 63 } //1 HeapReAlloc
		$a_01_5 = {44 65 6c 65 74 65 46 69 6c 65 57 } //1 DeleteFileW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}