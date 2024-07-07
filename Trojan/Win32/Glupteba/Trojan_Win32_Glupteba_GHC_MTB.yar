
rule Trojan_Win32_Glupteba_GHC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 08 81 c0 90 01 04 81 eb 90 01 04 4e 39 d0 75 90 01 01 21 fe c3 c3 04 00 90 00 } //10
		$a_03_1 = {31 06 81 c1 90 01 04 81 e9 90 01 04 81 c6 90 01 04 39 d6 75 90 01 01 83 ec 04 89 3c 24 5f 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}