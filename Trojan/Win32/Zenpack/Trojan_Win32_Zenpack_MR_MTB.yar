
rule Trojan_Win32_Zenpack_MR_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ee 05 03 [0-03] 81 3d [0-08] c7 05 [0-08] c7 05 [0-08] 90 18 [0-08] 33 [0-03] 33 [0-03] 2b [0-03] 83 [0-05] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}