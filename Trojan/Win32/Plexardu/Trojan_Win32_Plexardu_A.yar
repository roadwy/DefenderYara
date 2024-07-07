
rule Trojan_Win32_Plexardu_A{
	meta:
		description = "Trojan:Win32/Plexardu.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 4e 02 84 c9 74 02 30 0a 8a 0a f6 d1 84 c9 88 0a 74 03 } //1
		$a_03_1 = {80 78 0c 08 0f 85 90 01 04 80 78 0d 06 75 90 01 01 8a 48 14 84 c9 75 90 01 01 80 78 15 02 75 90 00 } //1
		$a_01_2 = {80 fa 7b 75 2b 8a 45 1b 3c 7d 75 0c 8a 4d 1c 80 f9 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}