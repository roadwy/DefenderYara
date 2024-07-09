
rule Trojan_Win64_Dridex_PQ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 8b 04 24 48 0d [0-04] 48 89 [0-03] 48 03 [0-03] 48 89 [0-03] 48 8b [0-03] 48 39 c1 0f 84 [0-04] e9 [0-04] b8 [0-04] 89 c1 48 2b [0-03] 48 89 [0-03] 8a [0-03] 80 [0-02] 88 [0-03] e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}