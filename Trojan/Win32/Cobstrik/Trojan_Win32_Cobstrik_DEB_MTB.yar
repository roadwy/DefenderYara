
rule Trojan_Win32_Cobstrik_DEB_MTB{
	meta:
		description = "Trojan:Win32/Cobstrik.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 25 d5 00 00 b8 25 d5 00 00 b8 25 d5 00 00 b8 25 d5 00 00 b8 25 d5 00 00 a1 90 01 04 a3 90 01 04 eb 00 31 0d 90 01 04 c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}