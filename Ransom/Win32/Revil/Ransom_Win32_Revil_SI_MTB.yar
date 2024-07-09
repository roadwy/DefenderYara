
rule Ransom_Win32_Revil_SI_MTB{
	meta:
		description = "Ransom:Win32/Revil.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 c9 03 c1 8a 0a 84 c9 75 ee 90 0a 15 00 69 c0 ?? ?? ?? ?? 42 0f b6 c9 03 c1 8a 0a 84 c9 75 ee } //1
		$a_03_1 = {8b 4f 3c 81 e6 ff ff 1f 00 33 db 8b 4c 39 78 03 cf 8b 41 24 8b 51 20 03 c7 89 45 f8 03 d7 8b 41 1c 03 c7 89 55 fc 89 45 f4 8b 41 18 89 45 08 85 c0 74 1e 8b 04 9a 03 c7 50 e8 ?? ?? ?? ?? 25 ff ff 1f 00 59 3b c6 74 12 8b 55 fc 43 3b 5d 08 72 e2 33 c0 5f 5e 5b 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}