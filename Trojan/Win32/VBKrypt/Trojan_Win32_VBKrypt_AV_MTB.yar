
rule Trojan_Win32_VBKrypt_AV_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AV!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 00 4f 00 4e 00 43 00 49 00 52 00 43 00 55 00 4d 00 53 00 43 00 52 00 49 00 50 00 54 00 49 00 56 00 45 00 } //1 NONCIRCUMSCRIPTIVE
		$a_01_1 = {44 00 49 00 53 00 54 00 4f 00 4d 00 41 00 54 00 49 00 44 00 41 00 45 00 } //1 DISTOMATIDAE
		$a_01_2 = {45 00 4b 00 53 00 4b 00 4c 00 55 00 44 00 45 00 52 00 49 00 4e 00 47 00 53 00 } //1 EKSKLUDERINGS
		$a_01_3 = {55 56 49 4c 4b 41 41 52 4c 49 47 48 45 44 45 4e 53 } //1 UVILKAARLIGHEDENS
		$a_01_4 = {4c 49 4e 4a 45 54 4c 4c 45 52 45 53 } //1 LINJETLLERES
		$a_01_5 = {54 49 4c 4c 41 44 45 4c 53 45 52 4e 45 } //1 TILLADELSERNE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}