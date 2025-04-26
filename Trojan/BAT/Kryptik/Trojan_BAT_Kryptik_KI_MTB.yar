
rule Trojan_BAT_Kryptik_KI_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.KI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 28 [0-04] 23 00 00 00 00 00 80 73 40 59 28 [0-04] b7 13 06 07 11 06 28 [0-04] 6f [0-04] 26 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d bf } //10
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=14
 
}