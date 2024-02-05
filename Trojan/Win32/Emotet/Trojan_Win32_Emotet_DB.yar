
rule Trojan_Win32_Emotet_DB{
	meta:
		description = "Trojan:Win32/Emotet.DB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 49 77 6d 54 51 70 46 78 48 73 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}