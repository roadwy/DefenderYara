
rule Ransom_Win32_Ryuk_ZZ{
	meta:
		description = "Ransom:Win32/Ryuk.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {55 8b ec 83 ec 90 01 01 53 90 03 06 04 33 c9 56 57 89 4d 56 57 c7 45 90 02 20 99 f7 7d 0c 8b 90 01 02 90 03 01 01 89 8b 90 01 02 90 03 01 01 89 8b 90 02 0a 88 45 ff 60 33 c0 8a 45 ff 33 c9 8b 4d f4 d2 c8 88 45 ff 61 8b 90 00 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}