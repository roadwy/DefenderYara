
rule Ransom_Win32_GandCrab_MTE_bit{
	meta:
		description = "Ransom:Win32/GandCrab.MTE!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 a1 90 01 03 00 50 6a 00 ff 15 90 01 03 00 90 00 } //1
		$a_03_1 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 0c 7d 1e 8b 4d 08 03 4d fc 0f be 11 89 55 f8 e8 90 01 03 ff 33 45 f8 8b 4d 08 03 4d fc 88 01 eb d1 90 00 } //1
		$a_03_2 = {8b f0 0f af 35 90 01 03 00 e8 90 01 03 ff 8d 44 06 01 a3 90 01 03 00 8b 35 90 01 03 00 c1 ee 10 e8 90 01 03 ff 23 c6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}