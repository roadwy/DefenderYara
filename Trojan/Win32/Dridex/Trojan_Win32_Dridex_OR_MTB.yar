
rule Trojan_Win32_Dridex_OR_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 eb 00 a1 [0-04] a3 [0-04] 8b 0d [0-04] 8b 11 89 15 [0-04] 8b 0d [0-04] a1 [0-04] a3 [0-04] 8b 15 } //1
		$a_02_1 = {89 08 8b e5 5d c3 90 09 21 00 33 15 [0-04] c7 05 [0-08] 01 15 [0-04] a1 [0-04] 8b 0d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}