
rule Ransom_Win32_Locky_D{
	meta:
		description = "Ransom:Win32/Locky.D,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 75 70 61 70 69 2e 64 6c 6c 00 71 77 65 72 74 79 00 } //10 敳畴慰楰搮汬焀敷瑲y
		$a_01_1 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //10 CryptImportKey
		$a_01_2 = {44 73 52 6f 6c 65 47 65 74 50 72 69 6d 61 72 79 44 6f 6d 61 69 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e } //10 DsRoleGetPrimaryDomainInformation
		$a_01_3 = {8b 41 08 8d 50 ff } //10
		$a_01_4 = {b9 00 08 00 00 8d 46 20 c6 00 00 40 49 75 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=50
 
}