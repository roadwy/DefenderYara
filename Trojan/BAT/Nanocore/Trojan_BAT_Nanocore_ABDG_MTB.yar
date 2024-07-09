
rule Trojan_BAT_Nanocore_ABDG_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c 00 07 15 58 0b } //4
		$a_01_1 = {50 00 35 00 33 00 59 00 53 00 43 00 59 00 52 00 42 00 56 00 48 00 48 00 55 00 50 00 38 00 47 00 34 00 37 00 42 00 37 00 35 00 59 00 } //1 P53YSCYRBVHHUP8G47B75Y
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}