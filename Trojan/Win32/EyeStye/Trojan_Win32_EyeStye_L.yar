
rule Trojan_Win32_EyeStye_L{
	meta:
		description = "Trojan:Win32/EyeStye.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 6f 63 6b 73 35 2e 64 6c 6c 00 47 65 74 50 6c 75 67 69 6e 49 64 00 } //1
		$a_03_1 = {8d 43 ff 3b c8 73 0c 8b 45 08 80 3c 01 3b 75 03 47 8b f1 3b 7d 0c 75 90 01 01 83 fe ff 74 09 90 00 } //1
		$a_03_2 = {ba 17 00 00 00 66 89 16 ff 15 90 01 04 66 89 46 02 8d 45 90 01 01 50 8b cf c7 46 04 00 00 00 00 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}