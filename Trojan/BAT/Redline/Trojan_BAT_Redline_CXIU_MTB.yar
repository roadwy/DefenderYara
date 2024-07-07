
rule Trojan_BAT_Redline_CXIU_MTB{
	meta:
		description = "Trojan:BAT/Redline.CXIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 6e 56 74 4d 79 41 36 49 41 3d 3d } //1 TnVtMyA6IA==
		$a_01_1 = {24 52 58 68 6a 5a 58 42 30 61 57 39 75 4f 69 42 4a 62 6e 5a 68 62 47 6c 6b 49 47 5a 76 63 6d 31 68 64 41 3d 3d } //1 $RXhjZXB0aW9uOiBJbnZhbGlkIGZvcm1hdA==
		$a_01_2 = {5a 47 46 6b 59 57 67 3d } //1 ZGFkYWg=
		$a_01_3 = {5a 47 52 6b 5a 47 52 6b 5a 47 52 6b 5a 41 3d 3d } //1 ZGRkZGRkZGRkZA==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}