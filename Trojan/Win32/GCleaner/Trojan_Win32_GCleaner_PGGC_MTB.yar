
rule Trojan_Win32_GCleaner_PGGC_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PGGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 01 1e 8b 7d d8 03 7d a4 03 fb 03 f8 c7 45 b8 89 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d b8 81 ef 89 15 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d e0 72 ba } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}