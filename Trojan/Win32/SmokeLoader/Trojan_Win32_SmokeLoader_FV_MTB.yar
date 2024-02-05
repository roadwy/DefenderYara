
rule Trojan_Win32_SmokeLoader_FV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 57 33 f6 56 8d 45 90 01 01 50 56 8d 85 90 01 04 50 56 56 68 e0 12 40 90 00 } //01 00 
		$a_01_1 = {50 8d 45 fc 50 8d 45 e4 50 8d 45 ec 50 8d 45 f4 50 53 } //00 00 
	condition:
		any of ($a_*)
 
}