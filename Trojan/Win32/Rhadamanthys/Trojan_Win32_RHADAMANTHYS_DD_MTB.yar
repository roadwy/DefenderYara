
rule Trojan_Win32_RHADAMANTHYS_DD_MTB{
	meta:
		description = "Trojan:Win32/RHADAMANTHYS.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 76 63 6f 64 65 63 2d 35 38 2e 64 6c 6c } //10 avcodec-58.dll
		$a_81_1 = {41 6c 70 68 61 42 6c 65 6e 64 } //1 AlphaBlend
		$a_81_2 = {61 76 31 5f 61 63 5f 71 75 61 6e 74 5f 51 33 } //1 av1_ac_quant_Q3
		$a_81_3 = {61 76 31 5f 61 63 5f 71 75 61 6e 74 5f 51 54 58 } //1 av1_ac_quant_QTX
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}