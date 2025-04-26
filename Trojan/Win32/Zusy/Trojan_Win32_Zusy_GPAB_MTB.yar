
rule Trojan_Win32_Zusy_GPAB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 99 8b f8 8b c6 33 fa 2b fa 8b 94 24 ?? 00 00 00 2b c2 99 33 c2 2b c2 3b f8 7e 2f 8b 44 24 ?? 8b d0 2b d1 8b 8c 24 ?? ?? 00 00 2b c8 0f af d1 85 d2 7e 0d 8b 94 24 ?? ?? ?? 00 89 54 24 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}