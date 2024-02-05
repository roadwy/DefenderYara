
rule Trojan_Win32_Redline_DAI_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 84 0c 90 02 04 88 84 14 90 02 04 8a 44 24 90 01 01 88 84 0c 90 02 04 0f b6 84 14 90 02 04 03 44 24 10 0f b6 c0 0f b6 84 04 90 02 04 30 86 90 02 04 46 81 fe 90 02 04 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}