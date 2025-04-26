
rule Trojan_BAT_DarkCloud_AAQD_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AAQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 70 73 74 6f 6e 65 50 72 6f 6a 65 63 74 32 6e 64 59 65 61 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 apstoneProject2ndYear.Resources.resources
		$a_01_1 = {34 64 34 61 33 38 66 39 2d 38 64 63 66 2d 34 62 32 61 2d 62 34 37 35 2d 35 61 66 30 63 33 61 62 31 33 31 34 } //1 4d4a38f9-8dcf-4b2a-b475-5af0c3ab1314
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}