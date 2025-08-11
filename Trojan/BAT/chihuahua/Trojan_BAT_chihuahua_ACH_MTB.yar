
rule Trojan_BAT_chihuahua_ACH_MTB{
	meta:
		description = "Trojan:BAT/chihuahua.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 6c 00 6f 00 77 00 65 00 72 00 73 00 2e 00 68 00 6f 00 6c 00 64 00 2d 00 6d 00 65 00 2d 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 78 00 79 00 7a 00 } //4 https://flowers.hold-me-finger.xyz
		$a_01_1 = {53 00 6e 00 79 00 61 00 6c 00 20 00 73 00 20 00 6d 00 61 00 7a 00 68 00 6f 00 72 00 61 00 20 00 63 00 65 00 70 00 69 00 2c 00 20 00 79 00 61 00 20 00 70 00 6f 00 76 00 65 00 73 00 69 00 6c 00 20 00 6e 00 61 00 20 00 73 00 65 00 62 00 79 00 61 00 20 00 67 00 6f 00 6c 00 64 00 } //2 Snyal s mazhora cepi, ya povesil na sebya gold
		$a_01_2 = {63 00 68 00 69 00 68 00 75 00 61 00 68 00 75 00 61 00 } //3 chihuahua
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=9
 
}