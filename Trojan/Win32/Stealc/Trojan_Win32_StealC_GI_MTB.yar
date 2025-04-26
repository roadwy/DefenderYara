
rule Trojan_Win32_StealC_GI_MTB{
	meta:
		description = "Trojan:Win32/StealC.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 37 89 44 24 04 8b 44 24 08 31 44 24 04 8a 4c 24 04 88 0c 37 83 fb 0f 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_StealC_GI_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce 80 fa 11 76 1d 0f b6 fa 83 ef 11 8d 4e 01 83 ff 04 0f 82 aa 00 00 00 8a 11 88 10 40 41 4f 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}