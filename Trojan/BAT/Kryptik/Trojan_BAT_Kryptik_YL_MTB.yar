
rule Trojan_BAT_Kryptik_YL_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.YL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 07 07 11 07 18 5a 18 6f 90 02 04 1f 10 28 90 02 04 9c 00 11 07 17 58 13 07 11 07 08 fe 04 13 08 11 08 2d d7 90 00 } //10
		$a_80_1 = {49 6e 76 6f 6b 65 } //Invoke  2
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=14
 
}