
rule Trojan_Win32_Azorult_RVB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 3c 0a 39 90 01 05 81 f7 90 01 0c 89 3c 08 90 01 06 83 e9 04 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}