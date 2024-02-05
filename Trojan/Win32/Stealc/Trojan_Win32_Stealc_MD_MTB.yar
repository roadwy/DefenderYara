
rule Trojan_Win32_Stealc_MD_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 08 88 0a eb 27 8b 55 08 03 95 90 01 04 0f b6 02 8b 8d 90 01 04 33 84 8d 90 01 04 8b 95 90 01 04 03 95 90 01 04 88 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}