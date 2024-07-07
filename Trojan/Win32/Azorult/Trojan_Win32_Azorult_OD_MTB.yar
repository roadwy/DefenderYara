
rule Trojan_Win32_Azorult_OD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 53 ff d7 46 3b 90 02 05 90 18 8b 90 02 05 8a 90 02 06 8b 90 02 05 88 90 02 02 81 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}