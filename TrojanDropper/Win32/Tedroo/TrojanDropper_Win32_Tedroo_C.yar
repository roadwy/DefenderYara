
rule TrojanDropper_Win32_Tedroo_C{
	meta:
		description = "TrojanDropper:Win32/Tedroo.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 cd 97 8e df 8b dd c2 c4 c1 8f dc df 93 c0 d2 ca 84 9f c8 } //00 00 
	condition:
		any of ($a_*)
 
}