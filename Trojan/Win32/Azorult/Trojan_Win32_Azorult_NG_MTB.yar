
rule Trojan_Win32_Azorult_NG_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 01 46 3b f7 90 18 81 [0-05] 90 18 8b [0-03] 8d [0-02] 90 18 a1 [0-04] 69 [0-05] 05 [0-04] a3 [0-04] 0f [0-06] 25 [0-04] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}