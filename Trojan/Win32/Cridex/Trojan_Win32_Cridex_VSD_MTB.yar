
rule Trojan_Win32_Cridex_VSD_MTB{
	meta:
		description = "Trojan:Win32/Cridex.VSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 6c 24 10 05 e8 1a 73 01 89 15 90 01 04 8b 15 90 01 04 89 84 2a 90 09 05 00 a1 90 00 } //02 00 
		$a_02_1 = {8b 44 24 40 0d 90 01 04 89 44 24 40 8b 44 24 28 32 0c 10 8b 54 24 2c 88 0c 1a 90 00 } //02 00 
		$a_02_2 = {8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 90 09 12 00 8b 3d 90 01 04 89 15 90 01 04 33 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}