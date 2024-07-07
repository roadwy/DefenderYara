
rule Trojan_Win32_Azorult_ER_MTB{
	meta:
		description = "Trojan:Win32/Azorult.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 73 67 6f 2e 65 78 65 } //1 csgo.exe
		$a_01_1 = {63 6c 69 65 6e 74 2e 64 6c 6c } //1 client.dll
		$a_01_2 = {63 68 65 61 74 2d 6d 65 6e 75 2e 70 64 62 } //1 cheat-menu.pdb
		$a_01_3 = {67 52 55 2e 6f 30 58 47 48 } //1 gRU.o0XGH
		$a_81_4 = {5a 49 5f 6b 53 26 61 69 } //1 ZI_kS&ai
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}