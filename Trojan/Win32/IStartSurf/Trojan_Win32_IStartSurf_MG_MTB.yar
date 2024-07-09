
rule Trojan_Win32_IStartSurf_MG_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 89 04 8a 41 81 f9 ?? ?? ?? ?? 7c 90 09 11 00 8b 44 8a ?? c1 e8 ?? 33 44 8a ?? 69 c0 } //1
		$a_02_1 = {33 0c ba 81 e1 ?? ?? ?? ?? 33 0c ba 8b c1 d1 e9 83 e0 ?? 69 c0 ?? ?? ?? ?? 33 c1 33 84 ba ?? ?? ?? ?? 89 04 ba 47 3b fe 7c 90 09 04 00 8b 4c ba } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}