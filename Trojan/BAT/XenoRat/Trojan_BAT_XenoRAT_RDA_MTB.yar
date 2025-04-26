
rule Trojan_BAT_XenoRAT_RDA_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6d 70 6f 72 74 61 6e 74 20 76 69 64 65 6f 20 66 69 6c 65 20 64 6f 20 6e 6f 74 20 64 65 6c 65 74 65 } //1 Important video file do not delete
		$a_01_1 = {63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 37 38 33 39 30 } //1 cc7fad03-816e-432c-9b92-001f2d378390
		$a_01_2 = {73 65 72 76 65 72 31 } //1 server1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}