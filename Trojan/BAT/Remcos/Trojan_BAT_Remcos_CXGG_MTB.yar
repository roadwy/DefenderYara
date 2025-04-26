
rule Trojan_BAT_Remcos_CXGG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.CXGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 57 35 30 5a 58 49 67 56 6d 46 73 64 57 55 67 62 32 59 67 54 69 41 36 49 41 3d 3d } //1 RW50ZXIgVmFsdWUgb2YgTiA6IA==
		$a_01_1 = {55 47 39 77 63 47 56 6b 49 45 56 73 5a 57 31 6c 62 6e 51 36 49 41 3d 3d } //1 UG9wcGVkIEVsZW1lbnQ6IA==
		$a_01_2 = {5a 47 46 6b 59 57 67 3d } //1 ZGFkYWg=
		$a_01_3 = {56 47 68 6c 49 48 5a 68 62 48 56 6c 49 47 6c 7a 4f 69 41 3d } //1 VGhlIHZhbHVlIGlzOiA=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}