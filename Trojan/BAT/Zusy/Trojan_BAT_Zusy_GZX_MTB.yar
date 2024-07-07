
rule Trojan_BAT_Zusy_GZX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 0d 6f 90 01 03 0a 13 0c 02 09 11 09 11 0c 28 90 01 03 06 13 0d 16 13 11 2b 1b 00 11 0e 11 11 8f 90 01 03 01 25 47 11 0d 11 11 91 61 d2 52 00 11 11 17 58 13 11 11 11 11 0e 8e 69 fe 04 13 12 11 12 2d d7 90 00 } //10
		$a_80_1 = {50 69 6c 6c 61 67 65 72 2e 64 6c 6c } //Pillager.dll  1
		$a_01_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
rule Trojan_BAT_Zusy_GZX_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 27 76 65 20 62 65 65 6e 20 68 61 63 6b 65 64 20 62 79 20 4c 6f 72 64 20 46 61 72 71 75 61 61 64 } //You've been hacked by Lord Farquaad  1
		$a_80_1 = {45 6e 63 72 79 70 74 65 64 4c 6f 67 2e 74 78 74 } //EncryptedLog.txt  1
		$a_80_2 = {4b 65 79 41 6e 64 49 56 2e 74 78 74 } //KeyAndIV.txt  1
		$a_01_3 = {53 65 76 65 6e 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //1 Seven_ProcessedByFody
		$a_80_4 = {53 65 76 65 6e 2e 64 6c 6c } //Seven.dll  1
		$a_01_5 = {4c 6f 67 44 65 63 72 79 70 74 65 64 } //1 LogDecrypted
		$a_01_6 = {4c 6f 67 45 6e 63 72 79 70 74 65 64 } //1 LogEncrypted
		$a_01_7 = {4f 70 65 6e 34 32 30 50 6f 72 74 } //1 Open420Port
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}