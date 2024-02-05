
rule Trojan_Win32_Redline_MKL_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8b 45 90 01 01 03 45 90 01 01 8a 08 88 4d 90 01 01 0f b6 4d 90 01 01 8b 45 90 01 01 33 d2 f7 75 90 00 } //01 00 
		$a_03_1 = {8a 45 ee 88 45 90 01 01 0f b6 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 2b c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 e9 90 01 04 8b 4d 90 01 01 33 cd e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}