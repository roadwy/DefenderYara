
rule Trojan_Win32_Redline_RC_MTB{
	meta:
		description = "Trojan:Win32/Redline.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 e4 50 6a 40 8b 0d 0c 30 41 00 51 68 90 01 01 14 40 00 ff 55 f8 89 45 e0 5f 5e 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}