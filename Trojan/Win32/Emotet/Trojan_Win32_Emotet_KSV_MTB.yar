
rule Trojan_Win32_Emotet_KSV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a d0 8a d9 0a c1 8b 4c 24 90 01 01 f6 d2 f6 d3 0a d3 22 d0 8b 44 24 90 01 01 88 14 08 90 09 04 00 8a 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}