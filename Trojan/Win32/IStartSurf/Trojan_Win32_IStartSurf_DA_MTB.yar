
rule Trojan_Win32_IStartSurf_DA_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 24 00 00 00 8b 3e ba c3 00 00 00 0f 45 d0 33 c0 8d 8f ?? ?? ?? ?? 3b fe ?? ?? 3b ce ?? ?? 8b 0e 30 14 01 40 3d 00 06 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}