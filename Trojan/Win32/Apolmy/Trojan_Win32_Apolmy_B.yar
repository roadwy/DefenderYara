
rule Trojan_Win32_Apolmy_B{
	meta:
		description = "Trojan:Win32/Apolmy.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 1d 03 00 00 00 c6 05 11 00 00 00 04 c7 05 5b 00 00 00 } //01 00 
		$a_01_1 = {b8 fb ff ff ff } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}