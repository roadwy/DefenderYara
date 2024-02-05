
rule Trojan_Win32_Raccoon_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8b c3 f7 f1 8b 45 f8 8a 0c 02 8d 14 33 8b 45 fc 8a 04 10 32 c1 43 88 02 3b df 72 } //00 00 
	condition:
		any of ($a_*)
 
}