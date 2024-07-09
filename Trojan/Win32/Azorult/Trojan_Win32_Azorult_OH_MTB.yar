
rule Trojan_Win32_Azorult_OH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 8d [0-02] 89 [0-02] e8 [0-04] 8b [0-05] 8b [0-05] 8d [0-02] e8 [0-04] 81 3d [0-0a] 90 18 33 [0-02] 89 [0-05] 89 [0-05] 8b [0-05] 29 [0-02] 81 3d [0-08] 90 18 ba [0-04] 8d [0-05] 90 18 29 11 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}