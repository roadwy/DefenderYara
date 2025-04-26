
rule Trojan_Win32_Tibs_GJ{
	meta:
		description = "Trojan:Win32/Tibs.GJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f2 52 66 ad 6b c0 ?? [0-06] 66 ad c1 (c0|c8) ?? [0-02] c1 (c0|c8) ?? 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}