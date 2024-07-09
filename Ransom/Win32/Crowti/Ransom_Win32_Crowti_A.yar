
rule Ransom_Win32_Crowti_A{
	meta:
		description = "Ransom:Win32/Crowti.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 a0 00 00 00 e8 18 00 00 00 59 89 45 fc 83 7d fc 00 74 ?? 8b 45 fc 2d ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_Crowti_A_2{
	meta:
		description = "Ransom:Win32/Crowti.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 8d 4d ?? 51 6a 00 68 ?? ?? ?? ?? 6a ff ff 55 } //1
		$a_03_1 = {0f b7 51 2c d1 ea 52 8b 45 ?? 8b 48 30 51 e8 ?? ?? ?? ?? 83 c4 08 3b 45 08 75 08 8b 55 ?? 8b 42 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}