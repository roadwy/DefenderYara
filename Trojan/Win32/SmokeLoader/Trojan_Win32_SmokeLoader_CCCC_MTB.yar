
rule Trojan_Win32_SmokeLoader_CCCC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CCCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 8b c8 c1 ea ?? 03 54 24 ?? c1 e1 ?? 03 4c ?? 24 03 c3 33 d1 33 d0 2b f2 8b ce } //1
		$a_03_1 = {8b c6 c1 e8 ?? 03 c5 33 c7 31 44 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}