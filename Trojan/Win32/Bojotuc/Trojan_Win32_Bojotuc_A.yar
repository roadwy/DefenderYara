
rule Trojan_Win32_Bojotuc_A{
	meta:
		description = "Trojan:Win32/Bojotuc.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 8b 51 24 03 54 24 10 8b 49 1c 0f b7 14 3a 8d 14 91 8b 0c 3a 03 cf 89 08 83 7c 24 0c 03 75 } //2
		$a_03_1 = {8a 10 80 f2 ?? 88 11 83 c0 02 41 66 83 38 00 75 ef } //2
		$a_03_2 = {8b 5c 24 08 91 80 90 09 07 00 53 b0 ?? b1 ?? b2 } //1
		$a_03_3 = {8b 7c 24 08 90 09 07 00 57 b0 ?? b1 ?? b2 } //1
		$a_03_4 = {53 56 57 b0 ?? b1 ?? b2 ?? 8b 7c 24 10 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}