
rule Ransom_MSIL_TRIPLEM_DA_MTB{
	meta:
		description = "Ransom:MSIL/TRIPLEM.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4c 30 4d 67 64 6e 4e 7a 59 57 52 74 61 57 34 75 5a 58 68 6c 49 47 52 6c 62 47 56 30 5a 53 42 7a 61 47 46 6b 62 33 64 7a 49 43 39 68 62 47 77 67 4c 31 46 31 61 57 56 30 } //1 L0MgdnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dzIC9hbGwgL1F1aWV0
		$a_81_1 = {56 46 4a 4a 55 45 78 46 54 53 68 4e 54 55 30 70 49 46 4a 46 51 6b 39 53 54 69 42 53 51 55 35 54 54 30 31 58 51 56 4a 46 49 48 59 30 } //1 VFJJUExFTShNTU0pIFJFQk9STiBSQU5TT01XQVJFIHY0
		$a_81_2 = {44 72 6f 70 53 68 69 74 2e 65 78 65 } //1 DropShit.exe
		$a_81_3 = {44 45 43 52 59 50 54 5f 46 49 4c 45 53 2e 74 78 74 } //1 DECRYPT_FILES.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}