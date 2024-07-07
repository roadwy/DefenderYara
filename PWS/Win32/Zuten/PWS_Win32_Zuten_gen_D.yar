
rule PWS_Win32_Zuten_gen_D{
	meta:
		description = "PWS:Win32/Zuten.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {8d bd f5 fe ff ff 59 88 9d f4 fe ff ff f3 ab 66 ab aa ff 15 } //2
		$a_01_1 = {63 61 63 68 65 66 69 6c 65 74 74 74 70 70 70 25 30 38 58 2e 72 74 72 } //2 cachefiletttppp%08X.rtr
		$a_01_2 = {c6 45 e5 72 c6 45 e6 73 c6 45 e7 49 c6 45 e8 6e c6 45 e9 66 c6 45 ea 6f ff 15 } //1
		$a_01_3 = {43 83 fb 14 7c bc 33 db 8d 85 f0 fb ff ff 53 50 8d } //1
		$a_01_4 = {77 69 6e 30 38 25 30 38 78 2e 64 6c 6c } //1 win08%08x.dll
		$a_01_5 = {c6 85 d0 fd ff ff 78 c6 85 d1 fd ff ff 57 88 9d d2 fd ff ff f3 ab aa 8d 85 c8 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}