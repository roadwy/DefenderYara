
rule Trojan_Win32_Azorult_OB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f6 39 3d 90 02 06 8b 90 02 05 8b 90 02 05 8d 90 02 03 8b 90 02 05 8a 90 02 03 8b 90 02 05 88 90 02 03 81 3d 90 02 08 90 18 46 3b 90 02 09 e8 90 02 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}