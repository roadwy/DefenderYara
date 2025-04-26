
rule Trojan_BAT_DarkTortilla_MBXS_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MBXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 46 53 46 55 37 78 49 6c 59 35 4e 36 73 44 41 48 4a 6b 4f 59 4c 2e 52 65 73 6f 75 72 } //3 YFSFU7xIlY5N6sDAHJkOYL.Resour
		$a_01_1 = {63 74 6f 72 00 7a 58 54 77 54 6e 64 6e 51 67 41 70 31 51 4a 46 4d 6f 51 4f 6b 41 38 75 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}