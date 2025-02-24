
rule Trojan_Win32_LummaC_ASU_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 0a 88 d4 f6 d4 20 c4 f6 d0 20 d0 08 e0 88 04 0e } //4
		$a_01_1 = {08 c4 30 d1 80 f4 01 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}