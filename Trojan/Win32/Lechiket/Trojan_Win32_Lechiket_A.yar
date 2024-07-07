
rule Trojan_Win32_Lechiket_A{
	meta:
		description = "Trojan:Win32/Lechiket.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 25 73 3f 26 69 64 3d 25 73 26 6d 61 72 6b 3d 25 73 } //1 GET /%s?&id=%s&mark=%s
		$a_01_1 = {6c 65 74 63 68 69 6b 00 } //1 敬捴楨k
		$a_01_2 = {5b 4e 45 54 57 4f 52 4b 20 44 41 54 41 3a 5d 00 } //1 乛呅佗䭒䐠呁㩁]
		$a_01_3 = {6e 5f 37 5f 33 32 00 } //1
		$a_01_4 = {8b 45 0c 33 c3 33 d2 6a 19 59 f7 f1 8b 45 08 01 7d 0c 80 c2 61 88 14 06 46 83 fe 08 72 e2 8b f8 4f f6 c3 01 c6 04 06 00 74 0f } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}