
rule Trojan_Win32_VBInject_BSA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 64 61 72 6b 20 65 79 65 5c 44 61 72 6b 20 45 59 45 } //10 \dark eye\Dark EYE
		$a_81_1 = {76 65 72 6d 69 2e 65 78 65 } //1 vermi.exe
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=10
 
}
rule Trojan_Win32_VBInject_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/VBInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b ec 83 ec 08 68 66 11 40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 81 ec 38 01 00 00 53 56 57 89 65 f8 c7 45 fc 48 } //10
		$a_81_1 = {52 65 67 65 6c 65 69 6e 67 61 6e 67 } //5 Regeleingang
		$a_81_2 = {46 65 72 6e 6f 73 74 61 62 74 65 69 6c 75 6e 67 52 } //5 FernostabteilungR
		$a_81_3 = {4d 46 64 63 68 65 6e 6b 72 63 6e 7a 65 44 } //5 MFdchenkrcnzeD
		$a_81_4 = {4b 46 73 65 73 63 68 6e 69 74 7a 65 6c 6e } //5 KFseschnitzeln
		$a_81_5 = {4c 61 6e 64 65 73 61 75 73 73 74 65 6c 6c 75 6e 67 73 67 65 62 } //5 Landesausstellungsgeb
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5) >=35
 
}
rule Trojan_Win32_VBInject_BSA_MTB_3{
	meta:
		description = "Trojan:Win32/VBInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 08 00 00 "
		
	strings :
		$a_01_0 = {89 85 e0 fe ff ff 89 45 ec 8b 4d ec b8 c6 04 00 00 3b c8 0f 8f 46 } //10
		$a_01_1 = {50 69 65 7a 6f 6b 65 72 61 6d 69 6b 62 61 75 74 65 69 6c 65 33 } //5 Piezokeramikbauteile3
		$a_01_2 = {68 72 75 6e 67 73 76 65 72 73 75 63 68 73 } //5 hrungsversuchs
		$a_01_3 = {42 65 69 73 70 69 65 6c 77 6f 72 74 73 37 } //5 Beispielworts7
		$a_01_4 = {4b 72 69 73 65 6e 6b 61 72 74 65 6c 6c 38 } //5 Krisenkartell8
		$a_01_5 = {4b 61 69 73 65 72 62 61 72 61 63 6b 65 6e } //5 Kaiserbaracken
		$a_01_6 = {42 65 68 65 6c 6c 69 67 65 6e 64 65 73 33 } //5 Behelligendes3
		$a_01_7 = {50 66 6c 65 67 65 74 69 65 72 65 36 } //5 Pflegetiere6
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=45
 
}