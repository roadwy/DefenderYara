
rule Trojan_BAT_Spynoon_ASEF_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0d 02 11 0b 11 0c 11 0d 28 90 01 01 00 00 06 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 00 11 08 17 59 13 08 11 08 16 fe 04 16 fe 01 13 0f 11 0f 2d 90 00 } //1
		$a_01_1 = {37 00 42 00 35 00 51 00 41 00 38 00 38 00 53 00 32 00 35 00 38 00 58 00 38 00 39 00 45 00 41 00 41 00 35 00 4e 00 47 00 52 00 35 00 } //1 7B5QA88S258X89EAA5NGR5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}