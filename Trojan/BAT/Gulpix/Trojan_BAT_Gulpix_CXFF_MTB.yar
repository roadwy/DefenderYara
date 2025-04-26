
rule Trojan_BAT_Gulpix_CXFF_MTB{
	meta:
		description = "Trojan:BAT/Gulpix.CXFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 29 04 00 00 e9 bc 00 00 00 8a 11 33 c0 84 d2 74 19 56 c1 c8 0d 0f be f2 80 } //1
		$a_01_1 = {fa 61 7c 03 83 c6 e0 03 c6 41 8a 11 84 d2 75 e9 5e c3 83 } //1
		$a_01_2 = {ec 10 64 a1 30 00 00 00 53 55 56 8b 40 0c 57 89 4c 24 14 8b 40 14 8b f8 89 44 24 1c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}