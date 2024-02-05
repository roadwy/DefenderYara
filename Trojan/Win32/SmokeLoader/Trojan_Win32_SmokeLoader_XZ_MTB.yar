
rule Trojan_Win32_SmokeLoader_XZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2a 39 39 c6 6a 90 01 01 b4 90 01 01 c5 69 90 01 01 4c 29 c6 4c 35 90 01 04 c6 c6 90 01 01 f9 4d 34 90 01 01 4c 2d 90 01 04 6a 90 00 } //01 00 
		$a_03_1 = {33 31 b8 d7 90 01 03 39 d2 3c 90 01 01 d2 cc 31 11 d2 3c 39 0b 55 90 01 01 d4 90 01 01 ff 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}