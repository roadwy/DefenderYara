
rule Trojan_Win32_Pitroj_A{
	meta:
		description = "Trojan:Win32/Pitroj.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6c 61 63 6b 68 6f 6c 65 63 } //1 Blackholec
		$a_01_1 = {63 61 70 74 75 72 65 5f 73 63 72 65 65 6e 74 } //1 capture_screent
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 20 50 72 6f 64 75 63 74 20 44 65 66 65 6e 64 65 72 2e 65 78 65 } //1 Microsoft Product Defender.exe
		$a_01_3 = {76 69 72 75 73 2e 70 79 } //1 virus.py
		$a_01_4 = {73 65 71 5f 64 61 74 61 2e 70 79 74 } //1 seq_data.pyt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}