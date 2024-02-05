
rule Trojan_Win32_Emotet_LG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 90 02 04 6a 00 ff 90 02 03 ff 90 02 03 89 44 90 02 02 ff 90 02 03 50 ff 54 90 02 02 83 c4 90 01 01 ff 90 02 03 8d 44 90 02 02 50 ff 90 02 03 6a 00 6a 01 6a 00 ff 74 90 02 02 ff 54 90 02 02 85 c0 90 02 06 8b 44 90 02 02 5f 5e 5d 5b 83 c4 90 01 01 c3 90 02 50 83 c4 90 01 01 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}