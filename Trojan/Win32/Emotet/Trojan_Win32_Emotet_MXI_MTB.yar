
rule Trojan_Win32_Emotet_MXI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {49 89 d8 ba 00 00 00 00 f7 f1 8a 44 15 00 30 04 1e 43 39 5c 24 } //1
		$a_80_1 = {46 24 71 70 38 31 38 4a 39 73 44 76 62 63 56 41 61 63 } //F$qp818J9sDvbcVAac  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}