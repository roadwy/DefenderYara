
rule Trojan_Win32_Fragtor_KXAA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 73 69 75 67 68 72 64 73 75 67 68 5f 73 72 75 67 73 72 68 75 67 } //1 dsiughrdsugh_srugsrhug
		$a_01_1 = {69 75 62 64 75 69 68 67 69 75 72 73 67 5f 73 75 69 67 68 73 75 67 73 } //1 iubduihgiursg_suighsugs
		$a_01_2 = {73 69 67 68 73 65 75 67 68 65 5f 73 68 75 67 73 67 68 75 73 65 67 } //1 sighseughe_shugsghuseg
		$a_01_3 = {76 62 68 6a 64 75 72 68 67 5f 65 73 75 68 67 73 68 65 } //1 vbhjdurhg_esuhgshe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}