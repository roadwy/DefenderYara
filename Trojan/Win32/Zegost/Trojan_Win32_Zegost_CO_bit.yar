
rule Trojan_Win32_Zegost_CO_bit{
	meta:
		description = "Trojan:Win32/Zegost.CO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 0a 75 c6 44 24 0b 72 c6 44 24 0c 6c c6 44 24 0e 67 c6 44 24 0f 2e c6 44 24 10 64 c6 44 24 11 61 c6 44 24 12 74 c6 44 24 13 00 } //1
		$a_01_1 = {8a 10 32 d1 02 d1 88 10 40 4e 75 f4 } //1
		$a_01_2 = {c6 45 c5 49 c6 45 c6 44 c6 45 c7 3a c6 45 c9 30 c6 45 ca 31 c6 45 cb 34 c6 45 cc 2d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}