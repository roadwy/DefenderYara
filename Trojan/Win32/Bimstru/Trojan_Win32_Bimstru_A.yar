
rule Trojan_Win32_Bimstru_A{
	meta:
		description = "Trojan:Win32/Bimstru.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 41 04 83 c1 04 3b c3 7c 05 32 c2 88 06 46 4f 3b fb 89 7d 10 7f e9 } //1
		$a_03_1 = {6a 40 68 80 04 00 00 8b 4d f4 51 8b 55 08 52 ff 15 90 01 02 40 00 85 c0 75 02 eb 73 90 00 } //1
		$a_01_2 = {c6 01 e9 8b 55 08 83 c2 01 89 55 08 8b 45 10 83 c0 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}