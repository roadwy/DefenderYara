
rule Trojan_Win32_Guloader_BEB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 00 66 00 6b 00 6f 00 72 00 74 00 6e 00 69 00 6e 00 67 00 65 00 6e 00 37 00 } //1 Afkortningen7
		$a_01_1 = {73 00 70 00 79 00 65 00 6e 00 64 00 65 00 73 00 73 00 74 00 6f 00 62 00 62 00 61 00 6c 00 6c 00 73 00 } //1 spyendesstobballs
		$a_01_2 = {53 00 75 00 63 00 72 00 6f 00 73 00 65 00 74 00 61 00 75 00 74 00 6f 00 6c 00 6f 00 67 00 69 00 73 00 65 00 73 00 6b 00 65 00 79 00 74 00 69 00 6e 00 67 00 77 00 36 00 } //1 Sucrosetautologiseskeytingw6
		$a_01_3 = {49 00 6e 00 74 00 65 00 72 00 76 00 61 00 72 00 79 00 69 00 6e 00 67 00 76 00 69 00 63 00 74 00 6f 00 72 00 69 00 61 00 73 00 74 00 72 00 6f 00 73 00 62 00 65 00 39 00 } //1 Intervaryingvictoriastrosbe9
		$a_01_4 = {47 00 55 00 52 00 55 00 53 00 52 00 45 00 45 00 58 00 43 00 48 00 41 00 4e 00 47 00 45 00 53 00 4e 00 59 00 54 00 54 00 45 00 56 00 49 00 52 00 4b 00 4e 00 49 00 } //1 GURUSREEXCHANGESNYTTEVIRKNI
		$a_01_5 = {54 00 41 00 4c 00 45 00 4e 00 54 00 46 00 55 00 4c 00 44 00 45 00 52 00 45 00 53 00 } //1 TALENTFULDERES
		$a_01_6 = {41 00 4e 00 44 00 52 00 45 00 57 00 41 00 52 00 54 00 48 00 41 00 } //1 ANDREWARTHA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}