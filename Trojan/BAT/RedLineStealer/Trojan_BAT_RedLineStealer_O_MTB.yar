
rule Trojan_BAT_RedLineStealer_O_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 1f 57 59 d2 81 ?? 00 00 01 00 07 17 58 0b 07 06 fe 04 0c 08 2d } //2
		$a_01_1 = {5f 63 72 79 70 74 65 64 } //1 _crypted
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}