
rule Trojan_BAT_Quasar_MB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 06 1a 73 23 00 00 0a 25 07 16 07 8e 69 6f 24 00 00 0a 73 25 00 00 0a 20 00 00 9f 24 20 00 80 48 28 6f 26 00 00 0a 8d 2c 00 00 01 0c 73 25 00 00 0a 08 6f 27 00 00 0a 25 08 16 08 8e 69 6f 24 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Quasar_MB_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 58 00 00 00 9e 00 00 00 47 00 00 00 11 00 00 00 01 00 00 00 03 00 00 00 15 00 00 00 02 00 00 00 03 00 00 00 0e } //10
		$a_01_1 = {6b 6f 69 00 73 65 72 76 65 72 31 2e 65 78 65 } //1
		$a_01_2 = {63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 33 38 36 } //1 cc7fad03-816e-432c-9b92-001f2d358386
		$a_01_3 = {73 65 72 76 65 72 31 2e 65 78 65 } //1 server1.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}