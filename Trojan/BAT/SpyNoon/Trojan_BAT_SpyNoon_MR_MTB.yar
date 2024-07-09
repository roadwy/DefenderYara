
rule Trojan_BAT_SpyNoon_MR_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 1f 00 d0 [0-04] 28 [0-04] 72 [0-04] 18 1b 8d [0-04] 25 16 72 [0-04] a2 25 17 20 [0-04] 8c [0-04] a2 25 1a 17 8d [0-04] 25 16 03 74 [0-04] 28 [0-04] a2 a2 28 [0-04] 74 [0-04] 13 20 02 11 20 72 [0-04] 6f [0-04] 7d [0-04] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}