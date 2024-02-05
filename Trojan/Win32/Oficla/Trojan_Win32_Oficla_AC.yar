
rule Trojan_Win32_Oficla_AC{
	meta:
		description = "Trojan:Win32/Oficla.AC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 89 e5 31 c0 8d 76 00 8b 14 c5 90 01 02 00 10 89 14 c5 90 01 02 00 10 8b 0c c5 90 01 02 00 10 89 0c c5 90 01 02 00 10 40 85 d2 75 df c9 c3 90 00 } //01 00 
		$a_00_1 = {69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}