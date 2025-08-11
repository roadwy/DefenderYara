
rule Trojan_Win32_Lazy_GVA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c1 99 f7 bd ?? ?? ?? ?? 8a 04 ?? 30 04 31 41 3b ?? 72 ec } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}