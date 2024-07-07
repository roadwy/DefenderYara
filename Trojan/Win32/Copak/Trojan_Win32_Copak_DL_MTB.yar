
rule Trojan_Win32_Copak_DL_MTB{
	meta:
		description = "Trojan:Win32/Copak.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 df 31 06 81 c7 01 00 00 00 bf e9 77 50 b1 68 1d e3 b7 6e 5f 81 c6 01 00 00 00 29 df 81 eb 86 e9 cc e0 21 fb 39 d6 75 } //2
		$a_01_1 = {83 ec 04 89 1c 24 5f 8b 0c 24 83 c4 04 bb 2b c1 5e 82 46 21 df 81 c7 01 00 00 00 81 fe 60 06 00 01 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}