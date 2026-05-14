
rule Trojan_Win32_Fragtor_MKD_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_01_0 = {e0 2e 72 73 72 63 00 00 00 00 20 00 00 00 e0 93 } //20
		$a_01_1 = {40 00 00 e0 2e 64 61 74 61 00 00 00 00 a0 0e 00 00 00 bd } //15
		$a_01_2 = {cf 73 94 f7 83 49 49 1b 78 06 00 45 4b e5 8f e8 } //10
		$a_01_3 = {72 53 9f 00 6e 40 f1 f1 96 36 65 a6 be 12 fb 14 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5) >=50
 
}