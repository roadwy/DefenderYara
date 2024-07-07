
rule Ransom_Win32_Conti_ZD{
	meta:
		description = "Ransom:Win32/Conti.ZD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 e0 89 45 94 8b 45 e4 89 45 98 8b 45 e8 89 45 9c 8b 45 ec 89 45 a0 8b 45 f0 89 45 a4 8b 45 f4 89 45 a8 8b 45 f8 89 45 ac 8b 85 60 ff ff ff 89 4d b0 89 4d b4 8d 4d 80 89 45 b8 8b 85 5c ff ff ff 56 57 c7 45 80 65 78 70 61 c7 45 84 6e 64 20 33 c7 45 88 32 2d 62 79 c7 45 8c 74 65 20 6b 89 45 bc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}