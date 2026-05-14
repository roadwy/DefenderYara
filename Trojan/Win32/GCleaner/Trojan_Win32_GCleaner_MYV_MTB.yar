
rule Trojan_Win32_GCleaner_MYV_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.MYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d d0 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}