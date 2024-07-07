
rule Trojan_Win32_VBKrypt_BL_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BL!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 41 00 4e 00 53 00 45 00 41 00 50 00 50 00 41 00 52 00 41 00 54 00 45 00 52 00 53 00 } //1 SANSEAPPARATERS
		$a_01_1 = {48 00 45 00 54 00 45 00 52 00 4f 00 43 00 48 00 52 00 4f 00 4d 00 4f 00 55 00 53 00 } //1 HETEROCHROMOUS
		$a_01_2 = {41 00 44 00 4f 00 50 00 54 00 49 00 56 00 4d 00 44 00 52 00 45 00 53 00 } //1 ADOPTIVMDRES
		$a_01_3 = {4f 55 54 53 48 4f 56 49 4e 47 4c } //1 OUTSHOVINGL
		$a_01_4 = {4e 4f 4e 43 4f 4e 46 4f 52 4d 49 53 } //1 NONCONFORMIS
		$a_01_5 = {52 41 43 45 4d 4f 43 41 52 } //1 RACEMOCAR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}