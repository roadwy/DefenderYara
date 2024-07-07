
rule Backdoor_Linux_Mirai_BN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 77 63 6c 76 67 61 6a } //1 hwclvgaj
		$a_00_1 = {63 66 6f 6b 6c 6b 71 76 70 63 76 6d 70 } //1 cfoklkqvpcvmp
		$a_00_2 = {71 77 72 67 70 74 6b 71 6d 70 } //1 qwrgptkqmp
		$a_00_3 = {6c 63 6f 67 71 67 70 74 67 70 } //1 lcogqgptgp
		$a_00_4 = {6e 6b 71 76 67 6c 6b 6c 65 } //1 nkqvglkle
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}