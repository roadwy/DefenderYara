
rule Trojan_Win32_Azorult_NZ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 04 31 81 3d [0-08] 90 18 46 3b ?? ?? ?? ?? ?? 90 18 8b [0-05] 8a [0-03] 8b } //1
		$a_02_1 = {88 04 31 81 3d [0-08] 90 18 46 3b [0-09] e8 [0-04] e8 [0-04] 8b } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}