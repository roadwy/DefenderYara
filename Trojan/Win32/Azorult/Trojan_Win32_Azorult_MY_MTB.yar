
rule Trojan_Win32_Azorult_MY_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 1e 83 90 02 02 90 18 46 3b f7 90 18 90 18 a1 90 02 04 69 90 02 05 81 90 02 05 a3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}