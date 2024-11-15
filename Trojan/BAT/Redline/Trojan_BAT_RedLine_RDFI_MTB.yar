
rule Trojan_BAT_RedLine_RDFI_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {36 63 34 65 62 31 38 37 2d 64 34 32 31 2d 34 38 64 33 2d 62 64 32 34 2d 33 34 63 33 30 62 35 36 30 61 36 64 } //2 6c4eb187-d421-48d3-bd24-34c30b560a6d
		$a_01_1 = {45 75 72 6f 53 70 61 72 20 49 6e 63 20 4f 70 74 69 54 65 63 68 20 53 75 69 74 65 } //1 EuroSpar Inc OptiTech Suite
		$a_01_2 = {53 68 61 70 69 6e 67 20 69 6d 6d 65 72 73 69 76 65 20 65 78 70 65 72 69 65 6e 63 65 73 20 74 68 72 6f 75 67 68 20 76 69 73 69 6f 6e 61 72 79 20 6f 70 74 69 63 73 20 61 6e 64 20 64 69 67 69 74 61 6c 20 69 6e 6e 6f 76 61 74 69 6f 6e } //1 Shaping immersive experiences through visionary optics and digital innovation
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}