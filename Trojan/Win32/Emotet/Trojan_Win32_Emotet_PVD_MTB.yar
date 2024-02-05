
rule Trojan_Win32_Emotet_PVD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 53 8d 34 07 e8 90 01 04 59 8b c8 33 d2 8b c7 f7 f1 8a 04 53 30 06 47 3b 7c 24 18 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}