
rule Trojan_Win32_Injuke_GNH_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 9d 90 01 04 48 78 00 00 da 0a 00 73 90 00 } //01 00 
		$a_80_1 = {53 54 44 43 6f 6e 69 6f 20 53 65 74 75 70 } //STDConio Setup  00 00 
	condition:
		any of ($a_*)
 
}