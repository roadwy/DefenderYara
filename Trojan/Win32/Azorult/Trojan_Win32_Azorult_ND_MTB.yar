
rule Trojan_Win32_Azorult_ND_MTB{
	meta:
		description = "Trojan:Win32/Azorult.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 37 83 [0-02] 90 18 46 3b f3 90 18 90 18 a1 [0-04] 69 [0-05] 81 3d [0-08] a3 [0-04] 90 18 81 [0-09] 56 0f [0-06] 81 [0-05] 81 [0-09] 90 18 8b ?? 5e c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}