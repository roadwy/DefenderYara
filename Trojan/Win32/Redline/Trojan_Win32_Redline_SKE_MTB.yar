
rule Trojan_Win32_Redline_SKE_MTB{
	meta:
		description = "Trojan:Win32/Redline.SKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 8b 7c 24 10 33 d2 8a 1c 3e 8b c6 f7 74 24 18 6a 00 6a 00 8a 82 90 01 04 32 c3 02 c3 88 04 3e ff 15 90 01 04 28 1c 3e 46 3b 74 24 14 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}