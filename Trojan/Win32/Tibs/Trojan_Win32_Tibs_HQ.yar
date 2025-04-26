
rule Trojan_Win32_Tibs_HQ{
	meta:
		description = "Trojan:Win32/Tibs.HQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 cb c3 ad 35 ?? ?? ?? ?? ab e2 f7 c3 8b 44 24 ?? c1 e8 ?? c1 e8 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}