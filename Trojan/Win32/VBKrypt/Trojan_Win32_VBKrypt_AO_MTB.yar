
rule Trojan_Win32_VBKrypt_AO_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AO!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 65 76 61 72 69 6e 67 73 66 6f 72 61 6e 73 74 61 6c 74 6e 69 6e 67 73 } //1 bevaringsforanstaltnings
		$a_01_1 = {41 6c 67 6f 72 69 74 6d 65 6b 61 6c 64 65 74 } //1 Algoritmekaldet
		$a_01_2 = {44 4f 42 42 45 4c 54 42 49 4c 4c 45 54 54 45 52 } //1 DOBBELTBILLETTER
		$a_01_3 = {48 00 79 00 70 00 65 00 72 00 69 00 6e 00 74 00 65 00 6c 00 6c 00 69 00 67 00 65 00 6e 00 63 00 65 00 34 00 } //1 Hyperintelligence4
		$a_01_4 = {50 00 52 00 45 00 44 00 49 00 53 00 41 00 53 00 54 00 52 00 4f 00 55 00 53 00 4c 00 59 00 } //1 PREDISASTROUSLY
		$a_01_5 = {41 00 53 00 54 00 52 00 4f 00 50 00 48 00 59 00 53 00 49 00 43 00 49 00 53 00 54 00 } //1 ASTROPHYSICIST
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}