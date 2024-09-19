
rule Trojan_Win32_Redline_MRF_MTB{
	meta:
		description = "Trojan:Win32/Redline.MRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 2c ?? 83 c4 ?? 03 44 24 ?? 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 0f 8b 44 24 ?? 85 c0 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}