
rule Trojan_Win32_GCleaner_KKA_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 6a 00 e8 ?? ?? ?? ?? 03 7d a4 81 ef ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d d0 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}