
rule Trojan_BAT_SpyNoon_KAJ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 00 43 00 68 00 6f 00 54 00 42 00 43 00 76 00 47 00 44 00 67 00 55 00 4f 00 42 00 47 00 45 00 66 00 66 00 56 00 6b 00 47 00 59 00 55 00 55 00 43 } //3
		$a_01_1 = {38 00 47 00 46 00 31 00 67 00 4b 00 44 00 67 00 51 00 6c 00 57 00 67 00 30 00 4f 00 42 00 41 00 6c 00 59 00 44 00 52 00 45 00 47 00 } //3 8GF1gKDgQlWg0OBAlYDREG
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}