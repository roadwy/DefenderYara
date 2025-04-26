
rule Trojan_Win32_Glupteba_PM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-06] 01 [0-03] 81 3d [0-08] 90 18 8b [0-03] 8b [0-03] 33 ?? 33 ?? 89 [0-03] 2b ?? 8b [0-06] 29 [0-03] 83 [0-07] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}