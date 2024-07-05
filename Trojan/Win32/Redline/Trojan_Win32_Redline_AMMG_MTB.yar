
rule Trojan_Win32_Redline_AMMG_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c6 59 59 8b 4c 24 90 01 01 0f b6 c0 8a 44 04 90 01 01 30 04 29 8d 4c 24 90 01 01 e8 90 01 04 45 3b ac 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}