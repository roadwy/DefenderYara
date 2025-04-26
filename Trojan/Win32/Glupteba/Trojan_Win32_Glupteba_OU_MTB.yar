
rule Trojan_Win32_Glupteba_OU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e8 05 c7 05 [0-08] c7 05 [0-08] 89 [0-02] 8b [0-05] 01 [0-02] 8b [0-02] 33 ?? 33 ?? 8d [0-05] e8 [0-04] 81 [0-09] 83 [0-06] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}