
rule Trojan_Win32_Tibs_JAC{
	meta:
		description = "Trojan:Win32/Tibs.JAC,SIGNATURE_TYPE_PEHSTR_EXT,57 04 57 04 01 00 00 "
		
	strings :
		$a_03_0 = {59 5a c1 e3 ?? c1 e3 ?? 8d 7c 1f ?? 81 ef ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? e2 c8 c3 } //1111
	condition:
		((#a_03_0  & 1)*1111) >=1111
 
}