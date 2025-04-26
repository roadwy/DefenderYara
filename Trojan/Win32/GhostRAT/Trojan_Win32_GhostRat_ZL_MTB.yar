
rule Trojan_Win32_GhostRat_ZL_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.ZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 e9 f5 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}