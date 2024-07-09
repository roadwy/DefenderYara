
rule Trojan_Win32_Dridex_PF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 83 [0-02] 89 [0-02] 81 [0-06] 0f [0-05] 0f [0-06] 8b [0-05] 8d [0-03] 89 [0-05] a1 [0-04] 03 [0-02] 8b [0-05] 89 [0-05] 69 [0-09] 0f [0-03] 03 ?? 66 89 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}