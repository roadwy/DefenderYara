
rule Trojan_Win32_Glupteba_OC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 c1 e8 05 03 [0-05] 03 [0-05] 03 ?? 33 ?? 33 ?? 81 [0-09] 89 [0-02] 90 18 33 ?? 89 [0-05] 89 [0-05] 8b [0-05] 29 [0-02] 81 [0-09] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}