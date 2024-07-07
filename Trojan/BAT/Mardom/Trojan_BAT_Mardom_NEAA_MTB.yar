
rule Trojan_BAT_Mardom_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {d0 1b 00 00 02 28 2a 00 00 0a 00 28 16 00 00 0a 72 43 00 00 70 28 17 00 00 0a 6f 18 00 00 0a 1f 28 28 31 00 00 0a 0a 06 14 28 32 00 00 0a 2c } //10
		$a_01_1 = {54 00 6e 00 52 00 44 00 63 00 6d 00 56 00 68 00 64 00 47 00 56 00 46 00 64 00 6d 00 56 00 75 00 64 00 41 00 3d 00 3d 00 } //2 TnRDcmVhdGVFdmVudA==
		$a_01_2 = {54 00 6e 00 52 00 42 00 62 00 47 00 78 00 76 00 59 00 32 00 46 00 30 00 5a 00 56 00 5a 00 70 00 63 00 6e 00 52 00 31 00 59 00 57 00 78 00 4e 00 5a 00 57 00 31 00 76 00 63 00 6e 00 6b 00 3d 00 } //2 TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}