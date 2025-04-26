
rule Trojan_Win32_Azorult_NB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {47 3b 7d 08 90 18 e8 [0-04] 30 [0-02] 83 [0-03] 75 } //1
		$a_02_1 = {47 3b 7d 08 90 18 90 18 a1 [0-04] 69 [0-05] 81 [0-09] a3 [0-04] 90 18 81 [0-09] 0f [0-06] 25 [0-04] c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}