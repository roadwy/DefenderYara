
rule Trojan_Win32_VBKrypt_AZ_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AZ!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 4f 4d 45 4e 54 41 4e 45 41 4c 4c } //1 MOMENTANEALL
		$a_01_1 = {4f 4d 53 56 49 4e 47 53 } //1 OMSVINGS
		$a_01_2 = {4e 6f 6e 63 6f 6e 66 69 64 65 6e 74 69 61 6c 69 74 79 36 } //1 Nonconfidentiality6
		$a_01_3 = {53 00 50 00 4e 00 44 00 45 00 53 00 4b 00 52 00 55 00 45 00 4e 00 } //1 SPNDESKRUEN
		$a_01_4 = {53 00 4c 00 41 00 47 00 4b 00 52 00 41 00 46 00 54 00 49 00 47 00 53 00 54 00 } //1 SLAGKRAFTIGST
		$a_01_5 = {4b 00 45 00 4e 00 44 00 45 00 52 00 45 00 53 00 } //1 KENDERES
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}