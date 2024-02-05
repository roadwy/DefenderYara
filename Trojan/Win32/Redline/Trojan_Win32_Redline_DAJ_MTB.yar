
rule Trojan_Win32_Redline_DAJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 84 0d 90 02 04 88 84 15 90 02 04 8a 85 90 02 04 88 84 0d 90 02 04 0f b6 84 15 90 02 04 03 85 90 02 04 0f b6 c0 0f b6 84 05 90 02 04 30 86 90 02 04 46 81 fe 90 02 04 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}