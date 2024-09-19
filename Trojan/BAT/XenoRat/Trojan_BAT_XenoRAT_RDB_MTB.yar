
rule Trojan_BAT_XenoRAT_RDB_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 37 38 33 39 32 } //2 cc7fad03-816e-432c-9b92-001f2d378392
		$a_01_1 = {44 69 73 70 6c 61 79 20 44 72 69 76 65 72 20 56 65 72 73 69 6f 6e 20 33 } //1 Display Driver Version 3
		$a_01_2 = {49 6d 70 6f 72 74 61 6e 74 20 64 69 73 70 6c 61 79 20 64 72 69 76 65 72 } //1 Important display driver
		$a_01_3 = {73 65 72 76 65 72 31 } //1 server1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}