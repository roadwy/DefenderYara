
rule Trojan_Win32_Lamechi_A{
	meta:
		description = "Trojan:Win32/Lamechi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 45 08 47 86 c8 61 03 f9 33 c7 2b d0 ff 4d 0c 75 be } //1
		$a_03_1 = {66 81 3f 41 4b 0f 85 90 01 03 00 56 8b 77 3c 03 f7 81 3e 50 45 00 00 0f 85 90 01 03 00 66 81 7e 14 e0 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}