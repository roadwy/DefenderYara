
rule Trojan_Win32_Cridex_RR_MTB{
	meta:
		description = "Trojan:Win32/Cridex.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c6 03 c2 8d 04 40 81 c3 90 01 04 2b c6 89 9c 2f 90 01 04 05 90 01 04 39 0d 90 01 04 72 90 01 01 29 35 90 01 04 8b c8 2b ce 83 c1 90 01 01 8b f0 2b 35 90 01 04 83 c5 90 01 01 83 c6 90 01 01 0f b7 f6 89 6c 24 90 01 01 81 fd 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}