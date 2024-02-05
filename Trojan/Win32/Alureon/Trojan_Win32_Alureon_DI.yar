
rule Trojan_Win32_Alureon_DI{
	meta:
		description = "Trojan:Win32/Alureon.DI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 74 24 04 90 01 01 d8 90 01 01 90 90 90 01 01 6a 30 90 01 01 d8 90 01 01 90 90 90 01 01 58 e9 90 01 02 00 00 90 01 03 e9 90 01 02 00 00 83 ec 04 97 d8 90 01 01 90 90 97 33 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}