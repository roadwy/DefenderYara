
rule Trojan_Win32_Azorult_OA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 01 89 [0-05] 8b [0-05] 3b [0-05] 73 ?? a1 [0-04] 03 [0-05] 8b [0-05] 03 [0-05] 8a [0-02] 88 ?? 81 [0-09] 90 18 [0-02] e8 [0-04] 68 [0-04] e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}