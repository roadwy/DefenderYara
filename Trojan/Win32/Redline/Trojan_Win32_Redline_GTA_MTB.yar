
rule Trojan_Win32_Redline_GTA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 c2 8b 45 08 01 d0 0f b6 00 0f be c0 6b c8 90 01 01 ba 90 01 04 89 c8 f7 ea 8d 04 0a c1 f8 90 01 01 89 c2 89 c8 c1 f8 90 01 01 29 c2 89 d0 ba 90 01 04 0f af c2 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}