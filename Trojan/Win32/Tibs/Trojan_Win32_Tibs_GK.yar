
rule Trojan_Win32_Tibs_GK{
	meta:
		description = "Trojan:Win32/Tibs.GK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 ad 69 c0 00 ?? ?? 00 [0-06] 66 ad c1 (c0|c8) ?? [0-04] c1 (c0|c8) ?? 93 81 c3 90 09 1b 00 [0-0c] (|) c3 c2 ?? ?? 66 ad } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}