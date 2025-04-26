
rule Trojan_Win32_Tibs_FO{
	meta:
		description = "Trojan:Win32/Tibs.FO,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff e0 8b 04 24 66 31 c0 8b 10 81 f2 ?? ?? ?? ?? 66 81 fa ?? ?? 74 07 2d 00 10 00 00 eb ea } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}