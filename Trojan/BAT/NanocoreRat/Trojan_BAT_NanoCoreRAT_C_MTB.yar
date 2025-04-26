
rule Trojan_BAT_NanoCoreRAT_C_MTB{
	meta:
		description = "Trojan:BAT/NanoCoreRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 } //2
		$a_01_1 = {00 00 01 25 16 1f 2d 9d 6f } //2
		$a_03_2 = {07 9a 1f 10 28 ?? ?? 00 0a d2 9c 07 17 58 0b } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}