
rule Trojan_Win32_Redline_DE_MTB{
	meta:
		description = "Trojan:Win32/Redline.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 f8 59 46 00 88 0c 02 } //01 00 
		$a_00_1 = {89 45 fc 8b c6 c1 e8 05 03 45 e8 8b ce c1 e1 04 03 4d e0 33 c1 33 45 fc 89 45 0c 8b 45 0c } //00 00 
	condition:
		any of ($a_*)
 
}