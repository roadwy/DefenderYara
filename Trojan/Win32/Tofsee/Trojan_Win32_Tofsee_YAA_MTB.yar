
rule Trojan_Win32_Tofsee_YAA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 7c 8b 45 ?? 33 c6 2b d8 89 9d c4 fd ff ff } //1
		$a_01_1 = {89 79 04 5f 5e 89 19 5b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}