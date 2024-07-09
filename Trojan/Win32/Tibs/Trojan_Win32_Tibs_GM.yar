
rule Trojan_Win32_Tibs_GM{
	meta:
		description = "Trojan:Win32/Tibs.GM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d6 52 66 ad c1 e0 ?? 66 ad c1 c8 ?? c1 c0 ?? 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}