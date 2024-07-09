
rule Trojan_Win32_Azorult_OB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f6 39 3d [0-06] 8b [0-05] 8b [0-05] 8d [0-03] 8b [0-05] 8a [0-03] 8b [0-05] 88 [0-03] 81 3d [0-08] 90 18 46 3b [0-09] e8 [0-04] e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}