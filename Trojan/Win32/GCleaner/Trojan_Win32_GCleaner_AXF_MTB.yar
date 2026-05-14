
rule Trojan_Win32_GCleaner_AXF_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d7 03 55 98 03 55 94 81 ea 2b fd 07 00 2b d0 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 13 83 c6 04 83 c3 04 3b 75 cc 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}