
rule Trojan_Win32_Redline_DAM_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 1c 90 02 04 88 84 3c 90 02 04 8a 44 24 13 88 84 1c 90 02 04 0f b6 84 3c 90 02 04 03 44 24 1c 0f b6 c0 0f b6 84 04 90 02 04 30 86 90 02 04 46 81 fe 90 02 04 0f 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}