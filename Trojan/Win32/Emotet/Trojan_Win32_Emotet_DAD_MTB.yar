
rule Trojan_Win32_Emotet_DAD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c6 2b c2 d1 e8 03 c2 8b 54 24 14 c1 e8 05 6b c0 90 01 01 8b ce 2b c8 8a 04 4a 30 04 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}