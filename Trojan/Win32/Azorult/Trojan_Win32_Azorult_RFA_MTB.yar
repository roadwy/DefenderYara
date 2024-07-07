
rule Trojan_Win32_Azorult_RFA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 33 45 90 01 01 81 3d 90 01 04 a3 01 00 00 c7 05 90 01 04 ee 3d ea f4 89 45 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}