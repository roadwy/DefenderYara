
rule Trojan_Win32_GCleaner_DSL_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.DSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 6a 00 e8 ?? ?? ?? ?? 03 f8 6a 00 e8 ?? ?? ?? ?? 03 7d a4 81 ef 5c 11 00 00 2b f8 31 3b 83 c6 04 83 c3 04 3b 75 d0 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}