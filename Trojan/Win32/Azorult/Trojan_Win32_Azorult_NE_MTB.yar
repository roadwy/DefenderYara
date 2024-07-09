
rule Trojan_Win32_Azorult_NE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 81 ff [0-04] 0f [0-02] 46 3b f7 90 18 8a [0-06] 88 } //1
		$a_02_1 = {30 04 1f 47 3b ?? 90 18 81 fe [0-04] 90 18 e8 } //1
		$a_02_2 = {30 04 1f 47 3b ?? 90 18 81 fe [0-04] 90 18 90 18 69 [0-09] 81 3d [0-08] a3 [0-04] 90 18 05 [0-04] a3 [0-04] c1 [0-02] 25 [0-04] c3 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}