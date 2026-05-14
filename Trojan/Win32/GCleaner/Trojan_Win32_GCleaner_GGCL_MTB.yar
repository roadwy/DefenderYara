
rule Trojan_Win32_GCleaner_GGCL_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.GGCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 ?? ?? ?? 03 ?? 03 [0-1f] 00 00 [0-0f] 81 ?? ?? ?? 00 00 2b [0-2f] 31 ?? 83 c3 04 83 c6 04 3b 5d ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}