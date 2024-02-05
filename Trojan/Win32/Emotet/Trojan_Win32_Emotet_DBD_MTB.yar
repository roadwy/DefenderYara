
rule Trojan_Win32_Emotet_DBD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 8b c6 33 d2 f7 f3 46 8a 44 55 00 30 44 3e ff 3b 74 24 1c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}