
rule Trojan_BAT_Disstl_AKL_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {43 3a 2f 74 65 6d 70 2f 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //C:/temp/Passwords.txt  3
		$a_80_1 = {43 3a 2f 74 65 6d 70 2f 53 79 73 74 65 6d 5f 49 4e 46 4f 2e 74 78 74 } //C:/temp/System_INFO.txt  3
		$a_80_2 = {73 65 6e 64 68 6f 6f 6b 66 69 6c 65 } //sendhookfile  3
		$a_80_3 = {53 74 65 61 6c 65 72 42 69 6e } //StealerBin  3
		$a_80_4 = {64 69 73 63 6f 72 64 61 70 70 } //discordapp  3
		$a_80_5 = {43 3a 2f 74 65 6d 70 2f 66 69 6e 61 6c 72 65 73 2e 76 62 73 } //C:/temp/finalres.vbs  3
		$a_80_6 = {57 65 62 42 72 6f 77 73 65 72 50 61 73 73 56 69 65 77 } //WebBrowserPassView  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}