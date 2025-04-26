
rule Trojan_Win32_Redline_DAM_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 1c [0-04] 88 84 3c [0-04] 8a 44 24 13 88 84 1c [0-04] 0f b6 84 3c [0-04] 03 44 24 1c 0f b6 c0 0f b6 84 04 [0-04] 30 86 [0-04] 46 81 fe [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}