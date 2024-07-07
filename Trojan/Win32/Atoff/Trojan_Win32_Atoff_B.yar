
rule Trojan_Win32_Atoff_B{
	meta:
		description = "Trojan:Win32/Atoff.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 57 ff 15 90 01 04 3d 00 68 5b 00 89 44 24 90 01 01 8b f0 72 05 be 00 68 5b 00 a1 90 01 04 85 c0 89 74 24 90 01 01 75 90 01 01 50 68 00 00 20 03 90 00 } //1
		$a_03_1 = {2b cf 83 f9 75 76 05 b9 75 00 00 00 89 4d 90 01 01 8b 55 0c 03 d7 8b c6 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}