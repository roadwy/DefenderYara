
rule Virus_Win32_Expiro_EK_MTB{
	meta:
		description = "Virus:Win32/Expiro.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 53 0f 84 89 00 00 00 0f 85 83 00 00 00 00 00 00 00 53 56 68 02 01 00 00 0f 84 90 00 00 00 0f 85 8a 00 00 00 0f 84 35 e1 ff ff 0f 85 60 c4 ff ff e9 0f 84 6c 01 00 00 89 c6 89 e0 50 0f 84 f7 01 00 00 0f 85 f1 01 00 00 00 00 00 00 5d c2 04 00 } //5
		$a_01_1 = {13 0f 84 41 01 00 00 0f 84 95 01 00 00 0f 85 8f 01 00 00 e9 0f 84 9e 00 00 00 47 3b 7c 1e 18 0f 82 70 01 00 00 0f 84 88 00 00 00 0f 85 82 00 00 00 00 00 00 00 57 56 83 ec 40 8b 44 24 54 8b 68 08 8b 38 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}