
rule Trojan_Win32_Vidar_AVR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 00 7c 63 40 00 40 37 40 00 34 37 40 00 8c 63 40 00 90 34 40 00 cc 34 40 00 12 54 4f 58 44 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_AVR_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.AVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 0c 24 00 03 00 00 01 c8 8d 0d 84 46 42 00 6b 14 24 0c 01 d1 89 01 8d 05 00 30 42 00 69 0c 24 00 03 00 00 01 c8 05 00 01 00 00 8d 0d 84 46 42 00 6b 14 24 0c 01 d1 89 41 04 8d 05 00 30 42 00 69 0c 24 00 03 00 00 01 c8 05 00 02 00 00 8d 0d 84 46 42 00 6b 14 24 0c 01 d1 } //2
		$a_01_1 = {a3 e4 4f 63 00 68 54 0c 42 00 ff 35 c4 51 63 00 e8 2a c7 fe ff a3 e8 4f 63 00 68 bd 0a 42 00 ff 35 c4 51 63 00 e8 15 c7 fe ff a3 ec 4f 63 00 68 13 09 42 00 ff 35 c4 51 63 00 e8 00 c7 fe ff a3 f0 4f 63 00 68 51 03 42 00 ff 35 c4 51 63 00 e8 eb c6 fe ff a3 98 4f 63 00 68 dc 09 42 00 ff 35 c4 51 63 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}