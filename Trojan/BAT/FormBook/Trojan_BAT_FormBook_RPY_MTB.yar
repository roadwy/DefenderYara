
rule Trojan_BAT_FormBook_RPY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 11 06 58 13 0c 07 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 13 0d 11 0d 11 0c 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0e 07 11 0b 11 08 6a 5d d4 11 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_RPY_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 11 04 17 58 13 07 07 11 04 91 11 05 11 06 91 61 13 08 07 11 04 11 08 07 11 07 07 8e 69 5d 91 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 06 09 5d 13 07 11 06 08 8e 69 5d 13 08 07 11 07 91 08 11 08 91 61 d2 13 09 11 09 07 11 06 17 58 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_RPY_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 13 0b 08 11 0b 91 11 08 58 13 0c 08 11 0a 91 13 0d 09 11 04 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 08 11 0a 11 10 11 08 5d d2 9c 11 04 17 58 13 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_RPY_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 13 05 07 11 04 91 11 05 61 13 06 11 04 17 58 07 8e 69 5d 13 07 07 11 07 91 13 08 11 06 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 09 07 11 04 11 09 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 0a 11 0a 2d a1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_RPY_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 73 00 69 00 64 00 3d 00 46 00 36 00 43 00 46 00 42 00 31 00 42 00 36 00 30 00 31 00 39 00 42 00 31 00 35 00 36 00 32 00 } //1 resid=F6CFB1B6019B1562
		$a_01_1 = {41 00 43 00 6d 00 34 00 53 00 66 00 62 00 6f 00 33 00 33 00 61 00 36 00 6a 00 49 00 34 00 } //1 ACm4Sfbo33a6jI4
		$a_01_2 = {68 00 69 00 73 00 74 00 6f 00 72 00 79 00 2f 00 } //1 history/
		$a_01_3 = {75 00 73 00 65 00 72 00 49 00 6e 00 66 00 6f 00 2f 00 75 00 73 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c 00 } //1 userInfo/users.xml
		$a_01_4 = {45 69 6f 6e 6c 65 77 } //1 Eionlew
		$a_01_5 = {6c 6f 61 64 48 69 73 74 6f 72 79 } //1 loadHistory
		$a_01_6 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
		$a_01_7 = {69 64 4e 75 6d 62 65 72 } //1 idNumber
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}