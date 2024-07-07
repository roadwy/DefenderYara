
rule Ransom_Win32_Ryuk_ZU{
	meta:
		description = "Ransom:Win32/Ryuk.ZU,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 5a 7d 45 33 c9 8b 55 fc c1 e2 05 03 55 08 89 0a 89 4a 04 89 4a 08 89 4a 0c 89 4a 10 89 4a 14 89 4a 18 89 4a 1c 8b 45 fc c1 e0 05 8b 4d 08 8b 55 fc 89 54 01 18 8b 45 fc c1 e0 05 8b 4d 08 c7 44 01 1c 00 00 00 00 eb ac } //100
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*100) >=101
 
}