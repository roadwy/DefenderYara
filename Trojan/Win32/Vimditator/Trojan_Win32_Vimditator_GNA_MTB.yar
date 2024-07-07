
rule Trojan_Win32_Vimditator_GNA_MTB{
	meta:
		description = "Trojan:Win32/Vimditator.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cd 8b d1 8d 74 24 90 01 01 8d 7c 18 90 01 01 6a 0a c1 e9 90 01 01 f3 a5 8b ca 83 e1 90 01 01 f3 a4 8b 7b 90 01 01 8b 35 90 01 04 03 fd 89 7b 90 01 01 ff d6 6a 0a ff d6 6a 0a ff d6 81 7b 90 01 01 78 da 04 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}