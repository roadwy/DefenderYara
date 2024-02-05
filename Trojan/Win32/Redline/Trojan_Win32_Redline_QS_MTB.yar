
rule Trojan_Win32_Redline_QS_MTB{
	meta:
		description = "Trojan:Win32/Redline.QS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 00 89 c2 89 d0 01 c0 01 d0 c1 e0 90 01 01 89 c3 8b 55 f8 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}