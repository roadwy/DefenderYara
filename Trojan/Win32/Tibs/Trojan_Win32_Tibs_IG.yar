
rule Trojan_Win32_Tibs_IG{
	meta:
		description = "Trojan:Win32/Tibs.IG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 83 c0 01 8b 18 be ?? ?? ?? ?? ff 94 1e ?? ?? ?? ?? 61 b9 ?? ?? 00 00 c9 c2 ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}