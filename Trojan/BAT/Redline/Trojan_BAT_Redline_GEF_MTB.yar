
rule Trojan_BAT_Redline_GEF_MTB{
	meta:
		description = "Trojan:BAT/Redline.GEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {34 00 44 00 2b 00 35 00 41 00 2b 00 39 00 7d 00 29 00 2b 00 7d 00 33 00 29 00 29 00 29 00 2b 00 7d 00 34 00 29 00 29 00 29 } //4  1
		$a_80_1 = {00 36 00 2b 00 36 00 46 00 2b 00 31 00 39 00 29 00 29 00 2b 00 7d 00 41 00 29 00 2b 00 7d 00 32 } //  1
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}