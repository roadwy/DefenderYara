
rule Trojan_Win32_Dridex_NP_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 a1 90 02 06 33 90 01 01 c7 05 90 02 08 01 90 02 05 a1 90 02 04 8b 90 02 05 89 08 8b 90 02 03 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}