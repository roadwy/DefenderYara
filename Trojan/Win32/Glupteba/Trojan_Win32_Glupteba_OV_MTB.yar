
rule Trojan_Win32_Glupteba_OV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c5 c1 e8 05 c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-06] 01 [0-03] 81 3d [0-08] 90 18 8b [0-03] 33 ?? 33 ?? 8d [0-06] e8 [0-04] 81 [0-05] 83 [0-07] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}