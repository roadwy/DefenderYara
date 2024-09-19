
rule Trojan_BAT_Remcos_NJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {00 03 8e 69 18 da 0b 73 ?? 00 00 0a 0c 07 0d 16 } //2
		$a_01_1 = {11 04 19 32 0a 11 04 1b fe 02 16 fe 01 } //2
		$a_01_2 = {06 9a 08 06 19 da 07 d8 } //2
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 69 6d 67 75 72 6c 2e 69 72 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //2 https://imgurl.ir/download.php
		$a_81_4 = {52 65 61 64 41 73 53 74 72 69 6e 67 41 73 79 6e 63 } //1 ReadAsStringAsync
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=9
 
}