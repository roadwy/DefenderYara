
rule Trojan_Win32_Dridex_OT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 e1 89 01 e8 [0-04] 8b [0-06] 8b [0-02] 0f [0-03] 8b [0-03] 0f [0-04] 29 f9 89 e7 89 37 89 [0-03] 89 [0-03] e8 [0-04] c6 [0-07] 8b [0-03] 01 c1 88 ca 88 [0-06] 8a [0-06] 8b 45 08 c7 [0-0a] c7 [0-0a] 8b [0-06] 88 14 08 eb 7c 66 8b [0-03] 66 35 [0-02] 66 89 [0-03] 8b [0-03] 89 e2 89 0a e8 [0-04] 0f [0-04] 01 c9 66 89 ?? 66 89 [0-03] 8b [0-06] 8b 55 08 81 [0-05] 89 [0-06] 8b [0-06] 0f [0-03] 29 c7 89 f8 88 c3 88 1c 0a eb 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}