
rule Trojan_Win32_Fareit_TD_MTB{
	meta:
		description = "Trojan:Win32/Fareit.TD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 6e fe 66 90 02 15 90 18 0f 6e da 90 02 15 31 f2 90 02 15 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}