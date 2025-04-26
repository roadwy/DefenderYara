
rule Trojan_Win32_Redline_DAI_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 0c [0-04] 88 84 14 [0-04] 8a 44 24 ?? 88 84 0c [0-04] 0f b6 84 14 [0-04] 03 44 24 10 0f b6 c0 0f b6 84 04 [0-04] 30 86 [0-04] 46 81 fe [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}