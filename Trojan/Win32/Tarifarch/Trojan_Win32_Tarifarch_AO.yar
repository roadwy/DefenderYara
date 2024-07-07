
rule Trojan_Win32_Tarifarch_AO{
	meta:
		description = "Trojan:Win32/Tarifarch.AO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 04 42 04 3e 04 20 00 12 04 4b 04 20 00 20 04 15 04 10 04 1b 04 2c 04 1d 04 2b 04 19 04 20 00 47 04 35 04 3b 04 3e 04 32 04 35 04 3a 04 } //2 что Вы РЕАЛЬНЫЙ человек
		$a_11_1 = {8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_11_1  & 1)*2) >=5
 
}