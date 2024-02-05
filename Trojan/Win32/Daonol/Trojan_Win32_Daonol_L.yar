
rule Trojan_Win32_Daonol_L{
	meta:
		description = "Trojan:Win32/Daonol.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 89 10 c6 85 90 01 02 ff ff 39 8d 85 90 01 02 ff ff c7 00 6d 69 64 69 90 09 06 00 8d 85 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {55 ff 53 04 ff d0 85 c0 0f 84 90 01 04 56 ff 53 10 97 6a 00 6a 01 50 8b 6b 24 03 6d 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}