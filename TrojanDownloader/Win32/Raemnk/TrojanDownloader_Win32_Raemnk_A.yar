
rule TrojanDownloader_Win32_Raemnk_A{
	meta:
		description = "TrojanDownloader:Win32/Raemnk.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {3a 00 5c 00 47 00 45 00 52 00 41 00 5c 00 62 00 69 00 6e 00 5c 00 } //1 :\GERA\bin\
		$a_00_1 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 45 00 4e 00 56 00 49 00 4f 00 5c 00 62 00 69 00 6e 00 5c 00 } //1 \Desktop\ENVIO\bin\
		$a_03_2 = {6c 54 ff 2a 23 4c ff 08 08 00 06 90 01 01 00 24 90 01 01 00 0d 44 00 90 01 01 00 6b 4a ff f4 ff c6 32 08 00 58 ff 50 ff 54 ff 4c ff 35 5c ff 1c af 00 00 53 3a 6c ff 90 01 01 00 4e 5c ff 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}
rule TrojanDownloader_Win32_Raemnk_A_2{
	meta:
		description = "TrojanDownloader:Win32/Raemnk.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff e8 90 01 04 c7 45 fc 03 00 00 00 c7 45 a0 90 01 04 c7 45 98 08 00 00 00 8d 55 98 90 00 } //10
		$a_03_1 = {66 8b c8 66 2b 4d 90 01 01 0f 80 90 01 02 00 00 66 03 ce 0f 80 90 01 02 00 00 0f bf c9 3b cb 7d 90 01 01 6a 1e 59 66 2b c1 b9 ff 00 00 00 0f 80 90 01 02 00 00 66 03 c6 0f 80 90 01 02 00 00 66 2b 4d 90 1b 00 0f 80 90 01 02 00 00 66 03 ce 0f 80 90 01 02 00 00 66 03 c1 0f 80 90 01 02 00 00 0f bf c8 90 00 } //1
		$a_03_2 = {66 8b c8 66 2b 4d 90 01 01 0f 80 90 01 02 00 00 66 03 ce 0f 80 90 01 02 00 00 0f bf c9 3b cb 7d 90 01 01 b9 ff 00 00 00 6a 1e 66 8b d1 59 66 2b 55 90 1b 00 0f 80 90 01 02 00 00 66 03 d6 0f 80 90 01 02 00 00 66 2b c1 0f 80 90 01 02 00 00 66 03 c6 0f 80 90 01 02 00 00 66 03 d0 0f 80 90 01 02 00 00 0f bf ca 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}