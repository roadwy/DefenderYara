
rule Trojan_Win32_Dridex_NI_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 89 10 8b 0d [0-04] 8b 15 [0-04] 8d [0-04] a3 [0-04] 8b 0d [0-04] 89 0d [0-04] 8b 15 [0-04] 89 15 [0-04] a1 [0-04] 83 c0 04 a3 [0-04] eb 00 e8 [0-04] 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}