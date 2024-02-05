
rule Trojan_Win32_Auhack_A{
	meta:
		description = "Trojan:Win32/Auhack.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 fb 20 7c 90 01 01 80 fb 78 7f 90 01 01 0f be c3 8a 80 f4 60 40 00 83 e0 0f eb 90 01 01 33 c0 0f be 84 c1 90 01 04 c1 f8 04 83 f8 07 89 45 c4 0f 87 90 01 04 ff 24 85 90 00 } //01 00 
		$a_02_1 = {41 00 79 00 6f 00 44 00 61 00 6e 00 63 00 65 00 90 02 08 48 00 61 00 63 00 6b 00 90 00 } //01 00 
		$a_00_2 = {4e 00 6f 00 6e 00 69 00 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}