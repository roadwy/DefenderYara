
rule Trojan_Win32_Nedsym_C{
	meta:
		description = "Trojan:Win32/Nedsym.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 57 0c ff b5 40 ff ff ff 68 90 01 02 59 00 ff 75 f4 68 90 01 02 59 00 8d 45 ec ba 05 00 00 00 e8 90 01 02 e6 ff a1 90 01 02 5a 00 80 38 00 74 6c 90 00 } //4
		$a_01_1 = {43 68 6f 6f 73 69 6e 67 20 52 65 73 70 6f 6e 63 65 73 2e 2e 2e 2e 00 } //1
		$a_01_2 = {2f 73 74 61 74 31 2e 70 68 70 00 } //1
		$a_01_3 = {73 79 73 72 65 67 00 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}