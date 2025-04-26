
rule Trojan_Win32_Glupteba_OM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-03] 01 [0-03] 81 3d [0-08] 90 18 8b [0-03] 33 ?? 33 ?? 8d [0-03] e8 [0-04] 81 3d [0-08] 90 18 8b [0-03] 29 [0-03] 83 [0-04] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}