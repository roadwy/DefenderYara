
rule Backdoor_Linux_Mirai_BN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 77 63 6c 76 67 61 6a } //01 00  hwclvgaj
		$a_00_1 = {63 66 6f 6b 6c 6b 71 76 70 63 76 6d 70 } //01 00  cfoklkqvpcvmp
		$a_00_2 = {71 77 72 67 70 74 6b 71 6d 70 } //01 00  qwrgptkqmp
		$a_00_3 = {6c 63 6f 67 71 67 70 74 67 70 } //01 00  lcogqgptgp
		$a_00_4 = {6e 6b 71 76 67 6c 6b 6c 65 } //00 00  nkqvglkle
	condition:
		any of ($a_*)
 
}