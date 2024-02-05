
rule Trojan_Win32_Vundo_gen_AZ{
	meta:
		description = "Trojan:Win32/Vundo.gen!AZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 04 83 04 24 06 8b 04 24 8b 0c 85 68 31 01 10 ff d1 } //00 00 
	condition:
		any of ($a_*)
 
}