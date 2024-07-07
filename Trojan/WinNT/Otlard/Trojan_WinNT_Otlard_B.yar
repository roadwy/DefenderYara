
rule Trojan_WinNT_Otlard_B{
	meta:
		description = "Trojan:WinNT/Otlard.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 7d 08 ad de 01 c0 75 0a b8 ad de 01 c0 } //1
		$a_03_1 = {68 ce c5 18 a7 e8 90 01 04 40 8b 18 80 fb e8 90 00 } //1
		$a_01_2 = {be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00 } //1
		$a_01_3 = {72 10 e8 04 00 00 00 0f 01 0c 24 5e a5 b8 04 00 00 00 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}