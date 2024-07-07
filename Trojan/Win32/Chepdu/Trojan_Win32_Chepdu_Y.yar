
rule Trojan_Win32_Chepdu_Y{
	meta:
		description = "Trojan:Win32/Chepdu.Y,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 2e 74 6c 62 00 00 00 00 5c 49 6d 70 6c 65 6d 65 6e 74 65 64 20 43 61 74 65 67 6f 72 69 65 73 } //1
		$a_01_1 = {0a 44 4f 4d 50 65 65 6b 57 64 00 } //1
		$a_01_2 = {33 45 04 89 45 fc 83 7d 08 00 74 45 68 00 01 00 00 8d 85 f8 fe ff ff 50 6a 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}