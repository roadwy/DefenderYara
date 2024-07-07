
rule Trojan_Win32_Copak_CU_MTB{
	meta:
		description = "Trojan:Win32/Copak.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 da 31 08 40 39 f0 75 df } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}