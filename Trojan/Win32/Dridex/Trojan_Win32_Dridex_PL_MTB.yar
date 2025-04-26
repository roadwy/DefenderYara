
rule Trojan_Win32_Dridex_PL_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 ca 83 e2 ?? 88 [0-03] 8b [0-03] 8a [0-02] 2a [0-06] 04 20 8b [0-03] 88 [0-02] 83 [0-03] 89 [0-03] 8b [0-03] 39 f9 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}