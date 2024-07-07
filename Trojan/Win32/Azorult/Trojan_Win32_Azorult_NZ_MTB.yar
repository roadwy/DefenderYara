
rule Trojan_Win32_Azorult_NZ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 04 31 81 3d 90 02 08 90 18 46 3b 90 01 05 90 18 8b 90 02 05 8a 90 02 03 8b 90 00 } //1
		$a_02_1 = {88 04 31 81 3d 90 02 08 90 18 46 3b 90 02 09 e8 90 02 04 e8 90 02 04 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}