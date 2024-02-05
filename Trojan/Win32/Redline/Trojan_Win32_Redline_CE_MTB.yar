
rule Trojan_Win32_Redline_CE_MTB{
	meta:
		description = "Trojan:Win32/Redline.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 4d fb 0f b6 45 fb 8b 0d 8c 52 48 00 03 4d e0 0f be 11 33 d0 a1 8c 52 48 00 03 45 e0 88 10 } //01 00 
		$a_01_1 = {8b 44 24 1c 89 44 24 18 8b 44 24 10 8b 4c 24 20 d3 e8 89 44 24 14 8b 44 24 40 01 44 24 14 33 54 24 18 8d 4c 24 30 89 54 24 30 } //00 00 
	condition:
		any of ($a_*)
 
}