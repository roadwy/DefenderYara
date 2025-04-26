
rule Trojan_Win32_Dridex_NG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 00 eb 00 8b [0-06] 33 [0-03] c7 05 [0-08] 8b [0-03] 01 [0-06] a1 [0-04] 8b 0d [0-04] 89 [0-03] 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}