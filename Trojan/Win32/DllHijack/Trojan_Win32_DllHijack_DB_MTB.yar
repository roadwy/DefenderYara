
rule Trojan_Win32_DllHijack_DB_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d0 f7 d8 d3 ea 89 56 ?? 8b d0 c0 e8 ?? 0f b7 0f 66 c1 c0 ?? 05 ?? ?? ?? ?? 58 66 33 cb 66 ff c1 0f b7 c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}