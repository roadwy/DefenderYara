
rule Trojan_Win32_Redline_MRD_MTB{
	meta:
		description = "Trojan:Win32/Redline.MRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 14 8a 44 14 ?? 88 44 0c ?? 88 5c 14 ?? 0f b6 44 0c ?? 8b 5c 24 ?? 03 c7 0f b6 c0 8a 44 04 ?? 30 83 ?? ?? ?? ?? 8b 44 24 ?? 2b c6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}