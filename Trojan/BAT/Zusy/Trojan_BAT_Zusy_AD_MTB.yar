
rule Trojan_BAT_Zusy_AD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 08 00 00 01 25 16 d0 0c 00 00 01 28 28 00 00 0a a2 28 2a 00 00 0a 28 29 00 00 0a 74 08 00 00 1b 73 2b 00 00 0a 72 cd 01 00 70 6f 2c 00 00 0a 6f 2d 00 00 0a 6f 2e 00 00 0a 6f 2f 00 00 0a 6f 30 00 00 0a } //2
		$a_01_1 = {63 33 61 61 32 62 37 30 2d 32 35 39 31 2d 34 34 63 33 2d 38 33 32 30 2d 36 38 64 38 63 36 35 62 66 64 34 63 } //1 c3aa2b70-2591-44c3-8320-68d8c65bfd4c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}