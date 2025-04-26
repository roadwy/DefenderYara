
rule Trojan_BAT_Mardom_MBFX_MTB{
	meta:
		description = "Trojan:BAT/Mardom.MBFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {17 0a 20 60 ea 00 00 0b 06 16 fe 01 13 0d 11 0d 2d 09 00 07 } //2
		$a_01_1 = {45 00 4f 00 66 00 57 00 53 00 75 00 67 00 53 00 39 00 74 00 6d 00 59 00 37 00 46 00 65 00 6d 00 59 00 67 00 65 00 31 00 34 00 30 00 4a 00 57 00 4a 00 2f 00 64 00 46 00 4b 00 6f } //2
		$a_01_2 = {52 00 6e 00 31 00 67 00 6f 00 61 00 47 00 33 00 55 00 43 00 } //2 Rn1goaG3UC
		$a_01_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}