
rule Trojan_Win32_Azorult_OH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 8d 90 02 02 89 90 02 02 e8 90 02 04 8b 90 02 05 8b 90 02 05 8d 90 02 02 e8 90 02 04 81 3d 90 02 0a 90 18 33 90 02 02 89 90 02 05 89 90 02 05 8b 90 02 05 29 90 02 02 81 3d 90 02 08 90 18 ba 90 02 04 8d 90 02 05 90 18 29 11 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}