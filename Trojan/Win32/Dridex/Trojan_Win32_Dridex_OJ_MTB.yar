
rule Trojan_Win32_Dridex_OJ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 e6 89 16 89 [0-03] e8 [0-04] 8b [0-03] 01 ?? 88 ?? 8b [0-03] 89 [0-06] 8b [0-03] 89 [0-06] 88 [0-03] 66 8b [0-06] 66 8b [0-06] 8a [0-03] 8b [0-02] 66 29 fe 66 89 [0-06] 8b [0-03] c7 [0-0a] 66 8b [0-06] 66 83 [0-02] 66 89 [0-06] 88 [0-02] e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}