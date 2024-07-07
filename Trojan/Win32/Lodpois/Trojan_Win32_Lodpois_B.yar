
rule Trojan_Win32_Lodpois_B{
	meta:
		description = "Trojan:Win32/Lodpois.B,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_03_0 = {85 c0 74 0b 8b d8 ff d3 6a ff e8 90 01 04 6a 00 e8 90 00 } //10
		$a_01_1 = {43 6f 6e 73 6f 6c 65 00 43 6f 64 65 00 00 00 00 55 8b ec 83 c4 f4 53 33 c9 89 4d f4 89 55 f8 89 45 fc 8b 45 fc e8 } //5
		$a_01_2 = {43 6f 6d 6d 46 75 6e 63 2e 64 6c 6c 00 47 65 74 49 6e 73 74 50 61 74 68 00 48 69 64 65 45 78 65 63 75 74 65 00 49 73 57 6f 77 36 34 00 } //5
		$a_01_3 = {4d 6f 64 75 6f 65 20 46 69 6c 65 20 50 61 74 68 00 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=25
 
}