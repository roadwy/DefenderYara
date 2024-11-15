
rule Trojan_BAT_Redline_WVAA_MTB{
	meta:
		description = "Trojan:BAT/Redline.WVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 53 68 61 70 69 6e 67 20 69 6d 6d 65 72 73 69 76 65 20 65 78 70 65 72 69 65 6e 63 65 73 20 74 68 72 6f 75 67 68 20 76 69 73 69 6f 6e 61 72 79 20 6f 70 74 69 63 73 20 61 6e 64 20 64 69 67 69 74 61 6c 20 69 6e 6e 6f 76 61 74 69 6f 6e 2e } //2 NShaping immersive experiences through visionary optics and digital innovation.
		$a_01_1 = {54 68 69 6e 6b 56 69 73 69 6f 6e 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 20 49 6e 63 2e } //2 ThinkVision Technologies Inc.
		$a_01_2 = {54 68 69 6e 6b 56 69 73 69 6f 6e 20 4f 70 74 69 54 65 63 68 20 53 75 69 74 65 } //1 ThinkVision OptiTech Suite
		$a_01_3 = {54 68 69 6e 6b 56 69 73 69 6f 6e 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 20 54 72 61 64 65 6d 61 72 6b } //1 ThinkVision Technologies Trademark
		$a_01_4 = {24 39 33 39 38 64 61 64 38 2d 34 39 61 63 2d 34 34 38 37 2d 38 65 62 65 2d 32 33 64 30 32 30 38 61 39 66 66 35 } //1 $9398dad8-49ac-4487-8ebe-23d0208a9ff5
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}