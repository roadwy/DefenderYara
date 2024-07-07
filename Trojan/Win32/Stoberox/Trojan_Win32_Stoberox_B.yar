
rule Trojan_Win32_Stoberox_B{
	meta:
		description = "Trojan:Win32/Stoberox.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d ff ff 00 00 75 90 01 01 8b 3f 8b 47 28 83 f8 64 73 02 eb 90 01 01 51 51 90 00 } //1
		$a_03_1 = {8b 7d fc 8b 77 3c 85 f6 74 90 01 01 33 d2 66 ad 84 c0 74 11 3c 41 72 06 3c 5a 77 02 0c 20 c1 c2 03 32 d0 eb e9 8b 75 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}