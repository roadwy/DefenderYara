
rule Trojan_Win32_Azorult_MR_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d9 33 d8 89 90 02 03 89 90 02 05 89 90 02 05 8b 90 02 05 29 90 02 03 81 3d 90 02 08 90 18 8b 90 02 05 29 90 02 03 ff 90 02 05 8b 90 02 03 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}