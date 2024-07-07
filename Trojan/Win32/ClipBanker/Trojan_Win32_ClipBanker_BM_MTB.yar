
rule Trojan_Win32_ClipBanker_BM_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 c2 88 06 8a 41 01 46 fe c2 41 84 c0 75 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}