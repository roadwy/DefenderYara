
rule Trojan_Win32_LummaC_ASGV_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 01 8b 4c 24 ?? 30 04 0a 8d 4c } //4
		$a_01_1 = {4a 41 48 4e 73 69 75 } //1 JAHNsiu
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}