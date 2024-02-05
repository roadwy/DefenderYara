
rule Trojan_Win32_Alureon_DB{
	meta:
		description = "Trojan:Win32/Alureon.DB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 0a 8b 11 8b 49 04 89 11 89 4a 04 6a 50 6a 00 50 e8 } //01 00 
		$a_01_1 = {74 64 6c 33 64 65 73 6b } //00 00 
	condition:
		any of ($a_*)
 
}