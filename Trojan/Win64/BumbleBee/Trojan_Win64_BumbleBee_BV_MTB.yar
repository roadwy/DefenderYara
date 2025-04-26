
rule Trojan_Win64_BumbleBee_BV_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 5a 45 55 45 42 } //2 DlZEUEB
		$a_01_1 = {52 41 58 78 79 4c 38 38 4d 44 } //2 RAXxyL88MD
		$a_01_2 = {47 65 74 53 74 64 48 61 6e 64 6c 65 } //1 GetStdHandle
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 41 } //1 CreateFileA
		$a_01_4 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //1 CreateNamedPipeA
		$a_01_5 = {57 61 69 74 4e 61 6d 65 64 50 69 70 65 41 } //1 WaitNamedPipeA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}