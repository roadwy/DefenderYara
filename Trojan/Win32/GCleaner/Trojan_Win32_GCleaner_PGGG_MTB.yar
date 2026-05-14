
rule Trojan_Win32_GCleaner_PGGG_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PGGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 01 1e ba 8a a5 08 00 8b 7d c8 03 fa 03 fb 03 f8 c7 45 a8 39 19 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d a8 81 ef 39 19 00 00 2b f8 6a 00 e8 [0-0f] f8 31 3e 83 c3 04 83 c6 04 3b 5d cc 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}