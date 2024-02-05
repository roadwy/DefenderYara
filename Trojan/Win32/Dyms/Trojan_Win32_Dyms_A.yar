
rule Trojan_Win32_Dyms_A{
	meta:
		description = "Trojan:Win32/Dyms.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 28 53 59 29 23 20 63 6d 64 00 00 2a 28 53 59 29 23 00 00 73 65 6e 64 20 3d 20 25 64 00 00 00 2a 28 53 59 29 23 20 00 63 6d 64 2e 65 78 65 00 65 78 69 74 } //01 00 
		$a_03_1 = {f2 ae f7 d1 49 51 8d 4c 24 90 01 01 68 90 01 04 51 e8 90 01 04 56 8d 54 24 90 01 01 68 90 01 04 52 e8 90 01 04 83 c4 18 83 fe ff 0f 84 90 01 04 b9 3f 00 00 00 33 c0 8d 7c 24 90 01 03 f3 ab 66 ab aa 8d 44 24 90 01 01 68 ff 00 00 00 50 55 e8 90 01 04 83 f8 ff 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}