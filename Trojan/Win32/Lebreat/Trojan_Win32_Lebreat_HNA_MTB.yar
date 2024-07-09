
rule Trojan_Win32_Lebreat_HNA_MTB{
	meta:
		description = "Trojan:Win32/Lebreat.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 07 00 00 00 89 d1 99 f7 f9 83 fb 0b 7f ?? 0f b6 44 2b c4 88 04 3a 83 fb 14 7e ?? 0f b6 44 2b c4 88 04 3a 4e } //1
		$a_03_1 = {55 89 e5 83 ec ?? c7 04 24 ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}