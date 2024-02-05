
rule Trojan_Win32_Redline_NM_MTB{
	meta:
		description = "Trojan:Win32/Redline.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 45 90 01 01 89 45 90 01 01 33 45 90 01 01 31 45 90 01 01 2b 5d 90 01 01 8d 45 90 01 01 89 5d 90 01 01 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}