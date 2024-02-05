
rule Trojan_Win32_SpyMal_A{
	meta:
		description = "Trojan:Win32/SpyMal.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 69 6b 6c 2e 70 64 62 } //01 00 
		$a_01_1 = {68 61 64 63 78 61 7a 2e 70 64 62 } //01 00 
		$a_01_2 = {79 61 62 65 73 61 72 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}