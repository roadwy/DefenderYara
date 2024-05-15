
rule Trojan_BAT_Zusy_GZX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {59 6f 75 27 76 65 20 62 65 65 6e 20 68 61 63 6b 65 64 20 62 79 20 4c 6f 72 64 20 46 61 72 71 75 61 61 64 } //You've been hacked by Lord Farquaad  01 00 
		$a_80_1 = {45 6e 63 72 79 70 74 65 64 4c 6f 67 2e 74 78 74 } //EncryptedLog.txt  01 00 
		$a_80_2 = {4b 65 79 41 6e 64 49 56 2e 74 78 74 } //KeyAndIV.txt  01 00 
		$a_01_3 = {53 65 76 65 6e 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //01 00  Seven_ProcessedByFody
		$a_80_4 = {53 65 76 65 6e 2e 64 6c 6c } //Seven.dll  01 00 
		$a_01_5 = {4c 6f 67 44 65 63 72 79 70 74 65 64 } //01 00  LogDecrypted
		$a_01_6 = {4c 6f 67 45 6e 63 72 79 70 74 65 64 } //01 00  LogEncrypted
		$a_01_7 = {4f 70 65 6e 34 32 30 50 6f 72 74 } //00 00  Open420Port
	condition:
		any of ($a_*)
 
}