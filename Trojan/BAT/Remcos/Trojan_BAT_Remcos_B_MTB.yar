
rule Trojan_BAT_Remcos_B_MTB{
	meta:
		description = "Trojan:BAT/Remcos.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 90 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f 9c 00 00 0a 1f 10 28 9d 00 00 0a } //2
		$a_01_1 = {35 31 63 62 66 66 63 61 2d 30 63 62 38 2d 34 37 33 63 2d 61 32 31 39 2d 38 64 36 36 30 35 32 65 38 38 64 34 } //1 51cbffca-0cb8-473c-a219-8d66052e88d4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}