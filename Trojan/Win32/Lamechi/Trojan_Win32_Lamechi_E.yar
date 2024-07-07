
rule Trojan_Win32_Lamechi_E{
	meta:
		description = "Trojan:Win32/Lamechi.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 45 08 47 86 c8 61 03 f9 33 c7 2b d0 ff 4d 0c 75 be } //1
		$a_03_1 = {81 39 4e 64 69 73 75 6f a1 90 01 04 83 78 34 00 74 64 90 00 } //1
		$a_03_2 = {81 3e 58 4a 56 32 0f 85 90 01 04 39 56 0c 0f 87 90 01 04 f6 c2 07 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}