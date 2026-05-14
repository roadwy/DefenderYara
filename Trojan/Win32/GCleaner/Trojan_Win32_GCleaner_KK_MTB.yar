
rule Trojan_Win32_GCleaner_KK_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 01 1e ba 8a a5 08 00 8b 7d c8 03 fa 03 fb 03 f8 c7 45 ?? ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? 03 7d a8 81 ef [0-17] f8 31 3e 83 c3 04 83 c6 04 3b 5d cc 72 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}