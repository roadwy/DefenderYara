
rule Trojan_Win32_Dreidel_MR_MTB{
	meta:
		description = "Trojan:Win32/Dreidel.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 [0-05] 8b [0-06] 01 [0-05] 8b [0-03] c1 [0-03] 03 [0-06] 8d [0-03] 33 [0-05] 81 3d [0-08] c7 05 [0-08] 90 18 8b [0-05] 33 [0-05] 89 } //1
		$a_02_1 = {c1 e8 05 03 [0-05] c7 05 [0-08] 89 [0-05] 33 [0-05] 33 [0-05] 2b [0-03] 8b [0-03] 29 [0-03] ff [0-03] 0f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}