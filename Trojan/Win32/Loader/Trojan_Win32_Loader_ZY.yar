
rule Trojan_Win32_Loader_ZY{
	meta:
		description = "Trojan:Win32/Loader.ZY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 68 40 00 00 00 68 90 01 01 0a 00 00 68 90 01 04 68 ff ff ff ff ff 15 90 00 } //01 00 
		$a_03_1 = {0a 00 00 68 90 01 04 68 90 01 04 b8 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}