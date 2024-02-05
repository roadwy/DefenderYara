
rule Trojan_Win32_Redline_GCK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 90 01 01 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d 90 01 04 93 00 00 00 74 90 01 01 68 90 01 04 8d 45 fc 50 e8 90 01 04 ff 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}