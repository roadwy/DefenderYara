
rule Trojan_Win32_SpyStealer_AU_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 d8 31 d2 8d 8d 90 02 04 f7 75 14 8b 45 08 0f be 34 10 e8 90 02 04 8d 8d 90 02 04 e8 90 02 04 69 c6 4d 91 fc 09 30 04 1f 43 eb b5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}