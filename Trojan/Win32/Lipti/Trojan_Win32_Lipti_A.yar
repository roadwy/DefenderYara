
rule Trojan_Win32_Lipti_A{
	meta:
		description = "Trojan:Win32/Lipti.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {84 c0 74 0d 81 3e c8 00 00 00 75 05 33 c0 40 eb 02 33 c0 } //1
		$a_01_1 = {8b 47 10 c6 04 03 00 8b 47 10 8a 0e 88 08 01 5f 10 } //1
		$a_01_2 = {8a 44 24 08 0f b6 c0 69 c0 01 01 01 01 8b d1 53 57 8b 7c 24 0c c1 e9 02 f3 ab } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}