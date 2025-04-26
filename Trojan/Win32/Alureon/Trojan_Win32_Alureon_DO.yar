
rule Trojan_Win32_Alureon_DO{
	meta:
		description = "Trojan:Win32/Alureon.DO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 37 0f b7 48 14 83 65 fc 00 8d 54 01 18 0f b7 40 06 33 c9 66 3b c8 73 20 } //1
		$a_01_1 = {7c e7 ff 75 0c 8b 55 14 8b 4d 10 8d 85 fc fe ff ff e8 } //1
		$a_01_2 = {b8 00 20 00 00 66 0b 46 16 83 c6 04 0f b7 c0 } //1
		$a_01_3 = {34 44 57 34 52 33 } //1 4DW4R3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}