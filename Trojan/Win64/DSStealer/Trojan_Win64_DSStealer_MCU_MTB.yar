
rule Trojan_Win64_DSStealer_MCU_MTB{
	meta:
		description = "Trojan:Win64/DSStealer.MCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 d2 81 c1 c6 72 22 29 d3 ca 41 89 c0 81 f2 c6 72 22 29 0f ca b8 01 00 00 00 29 d0 0f c8 } //1
		$a_01_1 = {ca 07 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 67 78 66 67 00 00 00 50 15 00 00 00 30 08 00 00 16 00 00 00 e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}