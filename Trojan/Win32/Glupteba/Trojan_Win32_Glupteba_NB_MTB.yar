
rule Trojan_Win32_Glupteba_NB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 e2 04 03 [0-06] 33 [0-03] 33 [0-03] 2b [0-03] 81 3d [0-08] 90 18 8b [0-06] 29 [0-06] 83 [0-08] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}