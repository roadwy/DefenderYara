
rule Trojan_Win32_Upatre_AHC_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 9d 64 ff ff ff 89 9d 54 ff ff ff 89 9d 44 ff ff ff 89 9d 34 ff ff ff 89 9d 30 ff ff ff c7 45 9c 4c 00 00 00 ff d7 } //10
		$a_01_1 = {8b 4d e4 c7 01 01 23 45 67 8b 55 e4 c7 42 04 89 ab cd ef 8b 45 e4 c7 40 08 fe dc ba 98 8b 4d e4 c7 41 0c 76 54 32 10 8b 55 e4 52 ff 15 } //5
		$a_81_2 = {53 6f 6d 65 20 65 76 69 6c 20 74 68 69 6e 67 73 20 68 61 70 70 65 6e 65 64 } //3 Some evil things happened
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_81_2  & 1)*3) >=18
 
}