
rule Trojan_Win32_DllHijack_DB_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d0 f7 d8 d3 ea 89 56 90 01 01 8b d0 c0 e8 90 01 01 0f b7 0f 66 c1 c0 90 01 01 05 90 01 04 58 66 33 cb 66 ff c1 0f b7 c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}