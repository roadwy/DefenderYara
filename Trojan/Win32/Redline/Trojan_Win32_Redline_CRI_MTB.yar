
rule Trojan_Win32_Redline_CRI_MTB{
	meta:
		description = "Trojan:Win32/Redline.CRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 0e 8b c6 f7 f5 6a 00 8a 82 90 01 04 32 c3 02 c3 88 04 0e ff 15 90 01 04 8b 4c 24 14 28 1c 0e 46 3b f7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}