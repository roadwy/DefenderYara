
rule Trojan_BAT_Remcos_AHBC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 6e 02 07 17 58 } //2
		$a_01_1 = {44 00 37 00 37 00 34 00 5a 00 34 00 37 00 38 00 56 00 34 00 53 00 37 00 33 00 39 00 32 00 47 00 47 00 42 00 48 00 35 00 34 00 47 00 } //1 D774Z478V4S7392GGBH54G
		$a_01_2 = {50 00 72 00 6f 00 6d 00 6f 00 43 00 6f 00 72 00 65 00 } //1 PromoCore
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}