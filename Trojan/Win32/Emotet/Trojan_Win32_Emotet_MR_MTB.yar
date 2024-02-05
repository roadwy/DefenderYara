
rule Trojan_Win32_Emotet_MR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d7 8b ca 8b c1 c7 05 90 01 08 01 05 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 89 11 5f 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}