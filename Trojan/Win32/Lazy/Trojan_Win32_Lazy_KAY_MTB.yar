
rule Trojan_Win32_Lazy_KAY_MTB{
	meta:
		description = "Trojan:Win32/Lazy.KAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 e8 4a be 06 00 8b 44 24 3c 8b 4c 24 50 39 c8 89 c2 8b 5c 24 6c 8b 6c 24 44 } //3
		$a_01_1 = {06 75 78 65 57 58 43 00 06 65 58 67 72 43 4e 00 06 71 49 59 78 4e 66 00 06 7a 5a 39 52 63 70 00 06 6e 4a 6e 33 32 6b } //3
		$a_01_2 = {07 64 69 42 70 52 37 63 01 07 57 72 69 74 65 54 6f 00 } //3 搇䉩剰挷܁牗瑩呥o
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}