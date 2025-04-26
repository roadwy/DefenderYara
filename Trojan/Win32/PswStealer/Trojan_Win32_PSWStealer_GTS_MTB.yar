
rule Trojan_Win32_PSWStealer_GTS_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 8a 01 01 00 00 8d 92 05 01 00 00 33 c0 83 e1 01 33 04 ca 33 44 ca 04 c3 } //10
		$a_01_1 = {0f b6 75 5d 0f b6 45 5e 0f b6 55 5f 0f b6 4d 60 c1 e6 18 c1 e0 10 c7 45 1c ff ff ff ff 0b f0 c1 e2 08 0b f2 0b f1 89 75 20 33 ff 89 7d 4c 89 7d 58 8b 44 24 38 3b 45 24 77 47 83 7d 48 00 75 1c } //10
		$a_01_2 = {68 74 74 70 3a 2f 2f 6c 61 64 79 2e 77 65 62 6e 69 63 65 2e 72 75 } //1 http://lady.webnice.ru
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 72 61 62 6f 74 61 2e 72 69 63 6f 72 2e 72 75 } //1 http://www.rabota.ricor.ru
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}