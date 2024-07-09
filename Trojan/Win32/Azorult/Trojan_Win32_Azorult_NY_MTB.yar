
rule Trojan_Win32_Azorult_NY_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 14 30 81 3d [0-08] 90 18 46 3b 35 [0-04] 90 18 8b [0-05] 8a [0-03] a1 } //1
		$a_02_1 = {88 14 30 81 3d [0-08] 90 18 46 3b [0-09] e8 [0-04] e8 [0-05] 8b } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}