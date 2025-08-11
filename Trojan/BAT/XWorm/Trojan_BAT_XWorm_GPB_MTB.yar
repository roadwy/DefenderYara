
rule Trojan_BAT_XWorm_GPB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 17 61 d1 0c 07 08 6f ?? 00 00 0a 26 09 17 58 0d 09 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_XWorm_GPB_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {4d 61 73 6f 6e 52 41 54 } //MasonRAT  2
		$a_80_1 = {61 70 70 64 61 74 61 73 } //appdatas  1
		$a_80_2 = {52 65 67 57 72 69 74 65 } //RegWrite  1
		$a_80_3 = {4d 61 73 6f 6e 4b 69 74 } //MasonKit  1
		$a_80_4 = {44 44 6f 73 54 } //DDosT  1
		$a_80_5 = {43 69 6c 70 70 65 72 } //Cilpper  1
		$a_80_6 = {69 6e 6a 52 75 6e } //injRun  1
		$a_80_7 = {74 61 73 6b 6b 69 6c 6c } //taskkill  1
		$a_80_8 = {63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6d 69 6e 75 74 65 } //create /f /sc minute  1
		$a_80_9 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=7
 
}