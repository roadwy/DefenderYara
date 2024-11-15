
rule Trojan_Win32_Azorult_SZSB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.SZSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c8 8b 45 f0 c1 e8 05 89 45 f8 8b 55 dc 01 55 f8 33 f1 81 3d a4 88 45 00 e6 09 00 00 c7 05 9c 88 45 00 ee 3d ea f4 75 0c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}