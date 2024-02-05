
rule Trojan_Win32_Redline_RS_MTB{
	meta:
		description = "Trojan:Win32/Redline.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 03 4d ec 8b da c1 e3 04 03 5d e8 03 c2 33 cb 33 c8 89 45 fc 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 c7 89 45 f4 8b 45 90 01 01 03 45 f8 89 45 fc 8b 45 90 01 01 83 0d 90 01 05 c1 e8 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 e4 01 45 90 01 01 ff 75 fc 8d 45 f4 50 e8 90 01 04 8b 45 f4 33 45 90 01 01 81 45 f8 90 01 04 2b d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}