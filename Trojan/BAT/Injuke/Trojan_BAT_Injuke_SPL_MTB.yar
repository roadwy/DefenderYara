
rule Trojan_BAT_Injuke_SPL_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 0f 00 00 0a 0a 28 10 00 00 0a 72 01 00 00 70 02 73 11 00 00 0a 28 12 00 00 0a 28 13 00 00 0a 28 14 00 00 0a 06 02 6f 15 00 00 0a 0b 25 07 28 16 00 00 0a 28 17 00 00 0a } //1
		$a_01_1 = {6f 00 6e 00 65 00 67 00 62 00 63 00 6c 00 6f 00 75 00 64 00 2e 00 63 00 66 00 64 00 } //1 onegbcloud.cfd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}