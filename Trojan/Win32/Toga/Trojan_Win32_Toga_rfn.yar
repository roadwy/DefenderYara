
rule Trojan_Win32_Toga_rfn{
	meta:
		description = "Trojan:Win32/Toga!rfn,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 45 f0 8b 45 fc 8b 40 28 03 45 f4 8b 55 f0 89 42 04 8b 45 f0 8b 55 f4 89 10 8b 45 fc 05 a0 00 00 00 8b 10 85 d2 74 0c } //1
		$a_03_1 = {8b 45 fc 83 c0 78 8b 10 85 d2 74 18 03 55 f4 8b 4d f0 89 91 90 01 04 8b 40 04 8b 55 f0 89 82 90 01 04 8b 45 fc 90 00 } //1
		$a_01_2 = {6a 00 6a 01 8b 45 f4 50 8b 45 f0 ff 50 04 85 c0 75 0a 8b 45 f0 33 d2 89 50 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Toga_rfn_2{
	meta:
		description = "Trojan:Win32/Toga!rfn,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f bf d0 8b 85 b0 fe ff ff 8d 8d 54 ff ff ff 33 c2 50 51 ff 15 90 01 04 8d 95 c4 fe ff ff 8d 85 54 ff ff ff 52 8d 8d 44 ff ff ff 90 00 } //1
		$a_01_1 = {8b c8 8b c6 99 f7 f9 c7 45 c4 03 00 00 00 89 55 cc 8b 55 e0 52 ff d7 8b c8 8b c6 99 f7 f9 8d 45 c4 8d 8d 34 ff ff ff } //1
		$a_01_2 = {8b 55 e0 89 45 bc 52 c7 45 b4 03 00 00 00 ff d7 8b c8 8b c6 99 f7 f9 c7 45 c4 03 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}