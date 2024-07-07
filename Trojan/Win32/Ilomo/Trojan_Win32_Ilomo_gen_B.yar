
rule Trojan_Win32_Ilomo_gen_B{
	meta:
		description = "Trojan:Win32/Ilomo.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 8d 45 fc 50 ff 75 08 ff 76 0c ff 77 08 ff 15 90 01 04 85 c0 74 08 8b 45 08 3b 45 fc 74 10 90 00 } //1
		$a_03_1 = {33 d2 42 eb 02 33 d2 52 53 ff 74 24 14 ff 71 08 ff 15 90 01 04 85 c0 74 02 b3 01 8a c3 90 00 } //1
		$a_03_2 = {c7 04 24 e8 03 00 00 8d 85 f4 fa ff ff 50 68 02 10 00 00 68 00 04 00 00 ff 15 90 01 04 85 c0 0f 84 90 01 02 00 00 80 bd 90 01 04 52 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}