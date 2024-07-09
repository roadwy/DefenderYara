
rule Trojan_Win32_RedLine_RDCN_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 3e 8b c6 f7 74 24 18 6a 00 6a 00 8a 82 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_RedLine_RDCN_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RDCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 ce 6c f7 d7 c1 df 36 f7 d8 42 0f c8 81 c7 ce 00 00 00 f7 e8 f7 d3 0f ce c1 d2 99 f7 d7 c1 d6 74 f7 da } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}