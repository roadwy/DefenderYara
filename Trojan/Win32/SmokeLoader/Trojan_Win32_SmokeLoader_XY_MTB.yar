
rule Trojan_Win32_SmokeLoader_XY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3e 87 e1 15 90 01 04 0d 90 01 04 b4 90 01 01 31 31 31 f9 0d 90 01 04 35 90 01 04 9c 90 00 } //01 00 
		$a_03_1 = {49 28 a0 44 90 01 03 11 d9 67 31 31 31 da 39 9d 90 01 04 11 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}