
rule Ransom_Win64_Akira_PB_MTB{
	meta:
		description = "Ransom:Win64/Akira.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 } //5 akira
		$a_01_1 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_01_2 = {2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d } //1 ---BEGIN PUBLIC KEY---
		$a_01_3 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 } //1 --encryption_path
		$a_01_4 = {2d 2d 73 68 61 72 65 5f 66 69 6c 65 } //1 --share_file
		$a_01_5 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 65 72 63 65 6e 74 } //1 --encryption_percent
		$a_01_6 = {74 68 65 20 69 6e 74 65 72 6e 61 6c 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 6f 66 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 20 69 73 20 66 75 6c 6c 79 20 6f 72 20 70 61 72 74 69 61 6c 6c 79 20 64 65 61 64 } //1 the internal infrastructure of your company is fully or partially dead
		$a_01_7 = {44 3a 5c 76 63 70 72 6f 6a 65 63 74 73 5c 61 6b 69 72 61 5c 61 73 69 6f 5c 69 6e 63 6c 75 64 65 5c 61 73 69 6f 5c 69 6d 70 6c } //1 D:\vcprojects\akira\asio\include\asio\impl
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}