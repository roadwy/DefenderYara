
rule Trojan_Win32_GCleaner_PGGK_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PGGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 03 45 c8 03 c3 03 c7 89 45 b4 c7 45 a4 2b 16 00 00 6a 00 e8 ?? ?? ?? ?? 8b 55 b4 03 55 a4 81 ea 2b 16 00 00 2b d7 2b d0 52 6a 00 e8 [0-1f] e8 ?? ?? ?? ?? 5a 2b d0 31 16 83 c3 04 83 c6 04 3b 5d cc 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}