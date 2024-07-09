
rule Trojan_Win64_Dridex_PW_MTB{
	meta:
		description = "Trojan:Win64/Dridex.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 f2 4c 8b [0-03] 49 81 [0-05] 4c 89 [0-03] 4c [0-04] 41 8a [0-02] 28 d8 48 8b [0-03] 48 89 [0-03] 4c 8b [0-03] 41 88 [0-02] 66 8b [0-03] 66 81 [0-03] 66 89 [0-03] 45 01 ?? 66 c7 [0-05] 44 89 [0-03] 48 29 ?? 48 89 [0-03] 44 8b [0-03] 45 39 ?? 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}