
rule Trojan_Win32_VidarStealer_RS_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c4 89 84 24 90 01 04 8b 0d 90 01 04 41 81 e1 ff 00 00 00 8a 91 90 01 04 0f b6 c2 03 05 90 01 04 53 25 ff 00 00 00 81 3d 90 01 04 fd 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}