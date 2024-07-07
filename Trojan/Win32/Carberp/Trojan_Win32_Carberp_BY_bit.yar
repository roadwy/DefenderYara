
rule Trojan_Win32_Carberp_BY_bit{
	meta:
		description = "Trojan:Win32/Carberp.BY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 28 8b 06 8a 0c 19 32 4c 04 10 88 0b 43 83 ed 01 75 90 01 01 0f 10 44 24 10 5f 90 00 } //2
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 72 00 75 00 } //1 http://www.yandex.ru
		$a_01_2 = {00 73 65 72 76 65 72 73 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}