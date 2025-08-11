
rule Trojan_Win32_Lazy_GX_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 11 33 d0 8b 45 08 03 45 f0 88 10 66 8b 4d ?? 66 83 c1 ?? 66 89 4d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}