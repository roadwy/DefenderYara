
rule Trojan_Win32_Redline_GFZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 1c 2e 8b c6 83 e0 03 ba 90 01 04 8a 80 a0 90 01 04 c3 02 c3 88 04 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}