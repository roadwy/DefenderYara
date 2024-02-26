
rule Trojan_Win32_Redline_GMW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 c4 40 50 e8 90 01 04 fe 0c 3e c7 04 24 90 00 } //0a 00 
		$a_03_1 = {33 d2 8b c6 f7 74 24 24 68 90 01 04 68 90 01 04 8a ba 90 01 04 32 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}