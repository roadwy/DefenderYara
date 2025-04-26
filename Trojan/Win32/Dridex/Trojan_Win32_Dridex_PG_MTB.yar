
rule Trojan_Win32_Dridex_PG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3b c1 74 19 0f [0-06] 8b c3 00 9a [0-04] 2b c1 83 [0-02] a3 [0-04] 83 [0-02] 83 [0-02] 7f ?? 85 f6 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}