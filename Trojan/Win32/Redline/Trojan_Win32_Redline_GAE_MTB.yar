
rule Trojan_Win32_Redline_GAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 33 8b c6 8b 4c 24 18 f7 75 08 83 c4 0c 8a 82 90 01 04 ba 90 01 04 32 c3 88 44 24 13 02 c3 88 04 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}