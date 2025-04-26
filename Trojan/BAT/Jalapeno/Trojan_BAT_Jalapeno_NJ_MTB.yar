
rule Trojan_BAT_Jalapeno_NJ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 fb 03 00 0a 6f fc 03 00 0a 28 fd 03 00 0a 28 fe 03 00 0a 28 07 00 00 2b 17 fe 02 0a 06 } //3
		$a_01_1 = {53 75 44 75 6e 67 53 6f 4c 75 6f 6e 67 } //1 SuDungSoLuong
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_Jalapeno_NJ_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 8d 5d 00 00 01 0b 16 72 01 00 00 70 72 01 00 00 70 07 06 02 7b 5b 00 00 04 28 0e 01 00 06 0c 08 06 18 59 fe 04 0d 09 13 04 11 04 2c 03 00 2b 07 06 18 5a 0a } //3
		$a_01_1 = {28 3f 00 00 0a 07 16 08 08 16 30 03 16 2b 01 17 59 6f 00 01 00 0a } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_BAT_Jalapeno_NJ_MTB_3{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 a3 00 00 0a 0a 28 e3 01 00 06 0b 07 1f 20 8d 58 00 00 01 25 d0 6a 02 00 04 28 8b 00 00 0a 6f c8 00 00 0a 07 1f 10 8d 58 00 00 01 25 d0 6c 02 00 04 28 8b 00 00 0a 6f c9 00 00 0a } //3
		$a_01_1 = {6f ca 00 00 0a 17 73 a4 00 00 0a 25 02 16 02 8e 69 6f a5 00 00 0a 6f a8 00 00 0a 06 6f a7 00 00 0a } //2
		$a_01_2 = {73 65 74 5f 43 6c 69 65 6e 74 43 72 65 64 65 6e 74 69 61 6c } //1 set_ClientCredential
		$a_01_3 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 31 2e 70 64 62 } //1 WindowsApplication11.pdb
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}
rule Trojan_BAT_Jalapeno_NJ_MTB_4{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 6f 23 00 00 0a a5 19 00 00 01 0c 12 02 28 24 00 00 0a 6f 25 00 00 0a 0d 12 02 28 26 00 00 0a 13 04 11 04 75 01 00 00 1b 2c 5a 11 04 74 01 00 00 1b 13 05 09 72 3b 00 00 70 1b 6f 27 00 00 0a 2c 15 06 09 72 4d 00 00 70 28 28 00 00 0a 28 1b 00 00 0a 13 06 2b 1c 09 28 29 00 00 0a 13 07 06 11 07 72 57 00 00 70 28 28 00 00 0a 28 1b 00 00 0a 13 06 11 06 28 1c 00 00 0a 2d 09 11 06 11 05 28 2a 00 00 0a 07 6f 2b 00 00 0a 3a 70 ff ff ff } //3
		$a_01_1 = {6f 2d 00 00 06 6f 3d 00 00 0a 25 03 6f 31 00 00 06 25 03 28 3e 00 00 0a 6f 34 00 00 06 6f 36 00 00 06 de 19 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_BAT_Jalapeno_NJ_MTB_5{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 55 00 00 70 6f ?? 00 00 0a 00 25 72 65 00 00 70 11 04 72 cf 00 00 70 28 28 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 17 } //3
		$a_01_1 = {74 00 72 00 6f 00 6a 00 61 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 trojam.Properties.Resources
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}