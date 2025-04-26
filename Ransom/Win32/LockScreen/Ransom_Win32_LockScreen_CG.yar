
rule Ransom_Win32_LockScreen_CG{
	meta:
		description = "Ransom:Win32/LockScreen.CG,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {3e 00 3e 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 2e 00 4e 00 61 00 6d 00 65 00 } //1 >>unlock.Name
		$a_01_1 = {3e 00 3e 00 63 00 6f 00 64 00 65 00 2e 00 4e 00 61 00 6d 00 65 00 } //1 >>code.Name
		$a_01_2 = {77 69 6e 6c 6f 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 } //2 winlock.Properties
		$a_01_3 = {6d 61 73 74 65 72 77 69 6e } //1 masterwin
		$a_01_4 = {ca 16 bf 16 d2 16 d4 16 c6 16 d4 16 da 16 cd 16 d3 16 } //5
		$a_01_5 = {0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 0c 08 07 8e 69 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*4) >=7
 
}