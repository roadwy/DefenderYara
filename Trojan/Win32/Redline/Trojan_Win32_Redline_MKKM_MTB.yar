
rule Trojan_Win32_Redline_MKKM_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ce c1 ee 90 01 01 03 75 90 01 01 03 c7 33 c1 33 f0 89 4d 90 01 01 89 45 90 01 01 89 75 90 01 01 8b 45 90 01 01 01 05 90 01 04 56 8d 45 90 01 01 50 e8 90 00 } //01 00 
		$a_03_1 = {01 45 fc 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}