
rule Trojan_Win32_Azorult_MR_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d9 33 d8 89 [0-03] 89 [0-05] 89 [0-05] 8b [0-05] 29 [0-03] 81 3d [0-08] 90 18 8b [0-05] 29 [0-03] ff [0-05] 8b [0-03] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}