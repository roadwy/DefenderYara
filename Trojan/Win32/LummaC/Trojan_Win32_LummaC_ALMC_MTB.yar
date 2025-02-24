
rule Trojan_Win32_LummaC_ALMC_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ALMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 de 83 e6 0c 89 c2 81 f2 46 dd 63 f6 01 f2 89 d6 21 ce 89 d7 31 cf 29 d7 01 f7 f7 d1 21 d1 09 f9 81 c1 cf 15 e1 4c 89 ca 83 e2 01 83 f1 01 8d 0c 51 88 4c 04 14 40 83 c3 02 83 f8 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}