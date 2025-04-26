
rule Trojan_Win32_GCleaner_CZ_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 03 54 24 ?? c1 e6 04 03 74 24 ?? 33 f2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}