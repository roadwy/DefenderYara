
rule Trojan_BAT_Xmrig_PSIV_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.PSIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 ff 00 00 0a 72 d4 03 00 70 28 00 01 00 0a 6f 01 01 00 0a 13 0c 08 28 0d 00 00 0a 2d 10 08 11 0c 28 02 01 00 0a 16 13 16 dd bc 02 00 00 11 05 11 0c 6f 03 01 00 0a 26 14 13 0d } //2
		$a_01_1 = {4a 00 47 00 56 00 75 00 64 00 6a 00 70 00 51 00 55 00 30 00 56 00 34 00 5a 00 58 00 56 00 6a 00 64 00 47 00 6c 00 76 00 62 00 6c 00 42 00 76 00 62 00 47 00 6c 00 6a 00 65 00 56 00 42 00 79 00 5a 00 57 00 5a 00 6c 00 63 00 6d 00 56 00 79 00 62 00 6d 00 4e 00 6c 00 50 00 53 00 4a 00 69 00 65 00 58 00 42 00 68 00 63 00 33 00 4d 00 69 00 44 00 51 00 6f 00 } //1 JGVudjpQU0V4ZXVjdGlvblBvbGljeVByZWZlcmVybmNlPSJieXBhc3MiDQo
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}