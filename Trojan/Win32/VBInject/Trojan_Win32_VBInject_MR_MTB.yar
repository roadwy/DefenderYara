
rule Trojan_Win32_VBInject_MR_MTB{
	meta:
		description = "Trojan:Win32/VBInject.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 d1 83 f8 [0-08] 90 18 81 [0-05] 01 ?? 83 [0-02] 3d [0-04] 8b ?? 3d [0-04] 83 [0-02] 90 18 81 [0-05] 81 [0-05] 3d [0-04] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}