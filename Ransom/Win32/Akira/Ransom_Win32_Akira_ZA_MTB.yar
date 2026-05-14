
rule Ransom_Win32_Akira_ZA_MTB{
	meta:
		description = "Ransom:Win32/Akira.ZA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 0f 57 c0 89 44 24 18 8b 45 0c 89 44 24 1c 8d 44 24 10 50 8d 44 24 08 66 0f 13 44 24 14 50 51 52 ff 36 c7 44 24 34 00 00 00 00 c7 44 24 18 00 00 00 00 } //1
		$a_01_1 = {8a 04 0e 84 c0 0f 84 e2 01 00 00 88 85 54 ff ff ff 0f b6 44 0e 01 88 85 55 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}