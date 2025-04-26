
rule Trojan_BAT_StealerC_MBZV_MTB{
	meta:
		description = "Trojan:BAT/StealerC.MBZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 07 93 20 ?? ?? ?? 00 61 02 61 d1 9d } //1
		$a_01_1 = {6e 00 41 00 64 00 78 00 57 00 00 47 62 00 61 00 62 00 65 00 6c } //1
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {41 69 67 71 79 64 76 78 74 } //1 Aigqydvxt
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}