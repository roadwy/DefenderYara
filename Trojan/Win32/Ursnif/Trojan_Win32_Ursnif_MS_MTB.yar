
rule Trojan_Win32_Ursnif_MS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c3 29 05 [0-04] 8b [0-03] 8a [0-03] 8b [0-03] 2a d1 83 [0-04] 05 [0-04] 80 [0-02] 89 07 83 [0-04] 8b [0-03] 88 [0-03] a3 [0-04] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}