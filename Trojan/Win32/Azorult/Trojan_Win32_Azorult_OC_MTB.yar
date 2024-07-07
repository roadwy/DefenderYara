
rule Trojan_Win32_Azorult_OC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 16 81 3d 90 02 08 90 18 46 3b 90 02 05 90 18 a1 90 02 04 8a 90 02 06 8b 15 90 00 } //1
		$a_02_1 = {88 0c 16 81 3d 90 02 08 90 18 46 3b 90 02 07 e8 90 02 04 e8 90 02 04 8b 90 02 05 8b 90 02 07 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}