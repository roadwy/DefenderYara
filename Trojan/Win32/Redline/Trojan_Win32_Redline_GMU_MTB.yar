
rule Trojan_Win32_Redline_GMU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 00 80 34 03 90 01 01 ff d7 6a 00 ff d6 8b 44 24 90 01 01 6a 00 80 34 03 90 00 } //0a 00 
		$a_03_1 = {8b c1 c1 e8 90 01 01 33 c1 69 c8 90 01 04 33 f1 3b d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}