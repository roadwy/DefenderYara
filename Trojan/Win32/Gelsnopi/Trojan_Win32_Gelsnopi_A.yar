
rule Trojan_Win32_Gelsnopi_A{
	meta:
		description = "Trojan:Win32/Gelsnopi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 32 00 00 00 f7 f9 83 fa 90 01 01 0f 8e af 00 00 00 6a 01 6a 05 6a 0f 90 00 } //01 00 
		$a_01_1 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 70 73 65 63 } //01 00 
		$a_01_2 = {26 72 76 72 3d 25 64 00 3f 72 76 72 3d 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}