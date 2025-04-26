
rule Trojan_Win32_Glupteba_MK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 c1 e8 05 8d [0-03] 89 [0-05] e8 [0-04] 8b [0-03] 8d [0-03] e8 [0-04] 33 [0-03] 8d [0-03] 8b d0 89 [0-03] c7 05 [0-08] e8 [0-04] 81 [0-09] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}