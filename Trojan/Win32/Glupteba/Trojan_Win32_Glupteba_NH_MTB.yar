
rule Trojan_Win32_Glupteba_NH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 e8 d3 e0 c1 [0-03] 03 [0-06] 55 03 [0-06] 89 [0-03] e8 [0-04] 33 [0-03] 89 [0-06] c7 05 [0-08] 8b [0-06] 29 [0-03] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}