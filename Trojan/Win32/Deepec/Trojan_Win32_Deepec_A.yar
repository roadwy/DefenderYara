
rule Trojan_Win32_Deepec_A{
	meta:
		description = "Trojan:Win32/Deepec.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 65 70 43 6d 64 00 } //1
		$a_01_1 = {47 45 54 20 2f 72 64 61 74 61 2f 3f 64 3d 63 69 64 3d 00 } //1
		$a_01_2 = {5c 73 63 2e 76 62 73 00 } //1
		$a_01_3 = {4c 61 73 74 44 75 6d 70 48 61 73 68 00 } //1
		$a_01_4 = {41 6d 6e 65 73 69 61 63 00 } //1
		$a_01_5 = {50 4f 53 54 20 2f 73 32 2f 3f 64 3d 63 69 64 3d 00 } //1
		$a_02_6 = {6a 06 6a 01 6a 02 ff 15 ?? ?? ?? 10 89 45 c8 6a 01 e8 ?? ?? ?? 00 59 50 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_02_6  & 1)*1) >=5
 
}