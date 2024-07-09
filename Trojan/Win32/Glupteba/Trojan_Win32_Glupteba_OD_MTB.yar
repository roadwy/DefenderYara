
rule Trojan_Win32_Glupteba_OD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 ea 05 8d [0-03] c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-06] 01 [0-05] c1 [0-05] 33 [0-03] 33 [0-03] 81 [0-09] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}