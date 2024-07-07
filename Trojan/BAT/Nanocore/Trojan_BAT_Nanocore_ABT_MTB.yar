
rule Trojan_BAT_Nanocore_ABT_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 6f 90 01 03 0a 07 1d 2c 04 17 58 0b 07 02 8e 69 32 db 06 6f 90 01 03 0a 25 2d 02 26 14 2a 90 00 } //2
		$a_01_1 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_BAT_Nanocore_ABT_MTB_2{
	meta:
		description = "Trojan:BAT/Nanocore.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 31 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 7e 90 01 03 04 06 28 90 01 03 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 90 01 03 00 fe 04 13 05 11 05 2d a9 28 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 28 90 01 03 06 72 90 01 03 70 6f 90 01 03 0a 80 90 01 03 04 2a 90 00 } //4
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {47 00 72 00 65 00 79 00 } //1 Grey
		$a_01_3 = {48 00 69 00 65 00 72 00 61 00 72 00 63 00 68 00 79 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Hierarchy.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}