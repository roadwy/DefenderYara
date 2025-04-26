
rule Trojan_Win32_Hioles_C{
	meta:
		description = "Trojan:Win32/Hioles.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 8b 11 ff d2 89 45 e8 8b 45 08 83 c0 14 50 8b 4d 08 8b 11 ff d2 } //1
		$a_01_1 = {6a 40 6a 00 6a 01 8d 55 f8 52 6a 00 6a 00 6a 00 8d 45 ec 50 8b 4d fc 51 8b 55 08 52 ff 55 f0 } //1
		$a_01_2 = {6a 40 56 6a 01 8d 45 f0 50 56 56 56 8d 45 f8 50 57 ff 75 08 ff 55 fc 85 c0 } //1
		$a_03_3 = {8d 4e 08 89 4c 24 10 8b 4c 24 10 0f b7 09 66 8b d9 66 c1 eb 0c 66 85 db 74 ?? 66 83 fb 03 75 0b 23 cf 03 0e 03 4d 08 01 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}