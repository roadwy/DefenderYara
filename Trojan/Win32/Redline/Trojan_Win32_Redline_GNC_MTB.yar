
rule Trojan_Win32_Redline_GNC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 c8 0f b6 f1 ba 90 01 04 e8 90 01 04 50 e8 90 01 04 59 8a 84 35 90 01 04 32 83 90 01 04 88 83 90 01 04 43 89 9d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}