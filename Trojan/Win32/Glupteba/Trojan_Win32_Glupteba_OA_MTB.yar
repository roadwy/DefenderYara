
rule Trojan_Win32_Glupteba_OA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 5e d3 e0 c1 ee 05 03 [0-06] 03 [0-06] 89 [0-03] 50 59 e8 [0-04] 33 ?? 89 [0-06] 89 [0-05] 8b [0-06] 29 [0-03] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}