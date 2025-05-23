
rule Trojan_Win32_Sopinar_D{
	meta:
		description = "Trojan:Win32/Sopinar.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 09 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 8d 49 01 34 ?? 88 41 ff 4a 75 f2 } //1
		$a_01_1 = {c7 06 25 73 5c 25 66 c7 46 04 73 5c } //1
		$a_01_2 = {c7 06 73 6e 78 68 c7 46 04 6b 2e 64 6c c6 46 08 6c } //1
		$a_03_3 = {8a 0c 06 8d 40 01 80 f1 ?? 88 48 ff 4a 75 f1 } //1
		$a_01_4 = {c7 02 63 68 72 6f c7 42 04 6d 65 2e 65 66 c7 42 08 78 65 } //1
		$a_01_5 = {c7 02 73 61 66 61 c7 42 04 72 69 2e 65 66 c7 42 08 78 65 } //1
		$a_01_6 = {c7 02 6f 70 65 72 c7 42 04 61 2e 65 78 c6 42 08 65 } //1
		$a_01_7 = {c7 02 6d 73 6d 73 c7 42 04 67 73 2e 65 66 c7 42 08 78 65 } //1
		$a_01_8 = {c7 06 6a 76 79 73 c7 46 04 63 6a 74 61 66 c7 46 08 76 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=3
 
}