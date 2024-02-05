
rule Trojan_Win32_Redline_MKR_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 1f 83 e3 90 01 01 8a 8b 90 01 04 32 ca 0f b6 da 8d 04 19 8b 75 90 01 01 88 04 37 e8 90 01 04 50 e8 90 01 04 59 28 1c 37 8b de 43 89 5d 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}