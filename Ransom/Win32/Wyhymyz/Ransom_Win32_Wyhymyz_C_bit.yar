
rule Ransom_Win32_Wyhymyz_C_bit{
	meta:
		description = "Ransom:Win32/Wyhymyz.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 01 68 10 66 00 00 ff ?? ?? ff 15 } //1
		$a_01_1 = {00 48 45 52 4d 45 53 00 } //1 䠀剅䕍S
		$a_01_2 = {55 00 4e 00 49 00 51 00 55 00 45 00 5f 00 49 00 44 00 5f 00 44 00 4f 00 5f 00 4e 00 4f 00 54 00 5f 00 52 00 45 00 4d 00 4f 00 56 00 45 00 } //1 UNIQUE_ID_DO_NOT_REMOVE
		$a_01_3 = {43 00 52 00 59 00 50 00 54 00 5f 00 49 00 4e 00 46 00 4f 00 52 00 4d 00 41 00 54 00 49 00 4f 00 4e 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 CRYPT_INFORMATION.html
		$a_01_4 = {00 52 53 41 31 00 08 00 00 01 00 01 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}