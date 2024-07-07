
rule Trojan_Win32_Azorult_MV_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e0 04 03 90 01 01 33 90 02 03 33 90 02 03 2b 90 01 01 81 90 02 09 90 18 8b 90 02 06 29 90 02 03 83 90 02 07 0f 90 02 0d 89 90 01 01 5f 5e 5d 89 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}