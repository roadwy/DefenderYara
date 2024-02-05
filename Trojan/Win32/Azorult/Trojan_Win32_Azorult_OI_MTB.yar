
rule Trojan_Win32_Azorult_OI_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 7d 74 89 90 02 05 89 90 02 05 8b 90 02 05 29 90 02 02 81 3d 90 02 08 90 18 81 90 02 09 ff 90 02 05 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}