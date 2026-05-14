
rule Trojan_Win32_Minix_SI_MTB{
	meta:
		description = "Trojan:Win32/Minix.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {55 6e 70 6c 65 61 73 61 6e 74 6c 79 5c 55 6e 69 6e 73 74 61 6c 6c 5c 74 61 6e 64 6b 6c 69 6e 69 6b 6b 65 6e 5c 75 6e 72 69 67 } //2 Unpleasantly\Uninstall\tandklinikken\unrig
		$a_81_1 = {73 6b 6e 73 6b 72 69 66 74 73 5c 74 6d 6d 65 72 70 72 6f 64 75 6b 74 69 6f 6e 65 72 6e 65 5c 70 6c 61 6e 6b 65 76 72 6b 65 74 } //1 sknskrifts\tmmerproduktionerne\plankevrket
		$a_81_2 = {52 65 69 6e 76 65 73 74 69 67 61 74 69 6e 67 37 33 5c 55 6e 69 6e 73 74 61 6c 6c 5c 6b 75 72 73 75 73 66 6f 72 6c 62 73 } //1 Reinvestigating73\Uninstall\kursusforlbs
		$a_81_3 = {62 72 61 6e 6b 6e 69 6e 67 65 72 6e 65 73 } //1 brankningernes
		$a_81_4 = {63 68 61 6d 6f 74 74 65 6c 65 72 73 2e 69 6e 69 } //1 chamottelers.ini
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}