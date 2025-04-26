
rule Backdoor_Win32_Remcos_PB_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 20 00 2f 00 63 00 73 00 74 00 61 00 72 00 74 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 76 00 6b 00 2e 00 6d 00 65 00 2f 00 6b 00 79 00 75 00 67 00 67 00 } //1 cmd /cstart https://vk.me/kyugg
		$a_00_1 = {43 00 3a 00 5c 00 4d 00 61 00 74 00 68 00 47 00 61 00 6d 00 65 00 5c 00 } //1 C:\MathGame\
		$a_01_2 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
		$a_01_3 = {67 65 74 5f 45 78 70 6c 6f 72 65 72 4c 6f 67 69 6e } //1 get_ExplorerLogin
		$a_01_4 = {43 00 72 00 65 00 61 00 74 00 65 00 54 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00 } //1 CreateTextFile
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}