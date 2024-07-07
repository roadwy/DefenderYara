
rule Trojan_BAT_BabaDeda_NEAA_MTB{
	meta:
		description = "Trojan:BAT/BabaDeda.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 33 66 64 31 31 37 65 2d 62 32 63 34 2d 34 66 30 32 2d 61 34 38 66 2d 34 62 36 36 33 33 32 37 35 66 32 61 } //10 e3fd117e-b2c4-4f02-a48f-4b6633275f2a
		$a_01_1 = {4f 72 69 6f 6e } //2 Orion
		$a_01_2 = {4f 72 67 2e 42 6f 75 6e 63 79 43 61 73 74 6c 65 2e 43 72 79 70 74 6f 2e 45 6e 67 69 6e 65 73 } //2 Org.BouncyCastle.Crypto.Engines
		$a_01_3 = {64 00 65 00 61 00 63 00 74 00 69 00 76 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 70 00 68 00 70 00 } //2 deactivation.php
		$a_01_4 = {2f 00 64 00 65 00 76 00 2f 00 64 00 69 00 73 00 6b 00 2f 00 62 00 79 00 2d 00 75 00 75 00 69 00 64 00 } //2 /dev/disk/by-uuid
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=18
 
}