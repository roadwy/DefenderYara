
rule Trojan_Win32_Emotet_MG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 90 02 03 51 6a 00 ff 55 90 01 01 89 90 02 02 8b 90 02 03 8b 90 02 02 50 8b 90 02 03 ff 90 02 02 83 90 01 01 0c 8b 90 02 03 8d 90 02 02 50 8b 90 02 03 6a 00 6a 01 6a 00 8b 55 90 01 01 52 ff 55 90 01 01 85 c0 90 02 02 33 c0 eb 90 02 c8 83 c4 0c 89 90 02 02 8b 90 02 02 89 90 02 02 ff 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}