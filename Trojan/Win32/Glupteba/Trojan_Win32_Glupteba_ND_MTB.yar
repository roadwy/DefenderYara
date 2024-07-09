
rule Trojan_Win32_Glupteba_ND_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b cb c1 e1 04 03 [0-06] 03 [0-03] 33 [0-03] 33 [0-03] 2b [0-03] 81 3d [0-08] 90 18 8d [0-06] e8 [0-04] 83 [0-07] 0f 85 } //1
		$a_02_1 = {8b d3 c1 e2 04 03 [0-06] 03 [0-03] 33 [0-03] 33 [0-03] 2b [0-03] 81 3d [0-08] 90 18 8d [0-06] e8 [0-04] 83 [0-07] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}