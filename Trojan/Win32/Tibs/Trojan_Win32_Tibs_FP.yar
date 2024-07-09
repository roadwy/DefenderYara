
rule Trojan_Win32_Tibs_FP{
	meta:
		description = "Trojan:Win32/Tibs.FP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff e0 8b 04 24 66 31 c0 89 c5 b8 ?? ?? ?? ?? 6a 00 ff 14 28 89 c2 69 d2 00 00 01 00 83 c4 04 29 c0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}