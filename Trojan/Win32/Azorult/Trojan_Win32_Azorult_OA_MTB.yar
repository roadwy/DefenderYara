
rule Trojan_Win32_Azorult_OA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 01 89 90 02 05 8b 90 02 05 3b 90 02 05 73 90 01 01 a1 90 02 04 03 90 02 05 8b 90 02 05 03 90 02 05 8a 90 02 02 88 90 01 01 81 90 02 09 90 18 90 02 02 e8 90 02 04 68 90 02 04 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}