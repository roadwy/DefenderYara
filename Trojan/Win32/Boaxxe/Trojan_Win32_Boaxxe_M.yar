
rule Trojan_Win32_Boaxxe_M{
	meta:
		description = "Trojan:Win32/Boaxxe.M,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {04 bf 2c 1a 72 06 04 fa 2c 1a 73 19 } //4
		$a_03_1 = {33 db eb 47 6a 28 6a 40 e8 ?? ?? ?? ?? 89 04 24 6a 00 8d 44 24 08 50 6a 04 8b 44 24 0c 50 6a 00 6a 00 68 18 00 22 00 } //4
		$a_01_2 = {64 72 64 6c 31 00 } //1 牤汤1
		$a_01_3 = {64 72 6c 73 33 32 77 2e 64 6c 6c 00 } //1
		$a_01_4 = {73 6d 33 32 77 69 6e 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}