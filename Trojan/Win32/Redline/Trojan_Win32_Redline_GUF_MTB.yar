
rule Trojan_Win32_Redline_GUF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0f be c0 69 c8 90 01 04 ba 90 01 04 89 c8 f7 ea 8d 04 0a c1 f8 90 01 01 89 c2 89 c8 c1 f8 90 01 01 29 c2 89 d0 89 c2 89 d0 c1 e0 90 01 01 29 d0 89 c1 8b 55 90 01 01 8b 45 90 01 01 01 d0 31 cb 89 da 88 10 83 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}