
rule Trojan_Win32_Dridex_NP_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 a1 [0-06] 33 ?? c7 05 [0-08] 01 [0-05] a1 [0-04] 8b [0-05] 89 08 8b [0-03] 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}