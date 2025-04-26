
rule Trojan_Win32_StealC_ZT_MTB{
	meta:
		description = "Trojan:Win32/StealC.ZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 03 85 ?? ?? ?? ?? 03 ce 33 c1 33 45 ?? 2b d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}