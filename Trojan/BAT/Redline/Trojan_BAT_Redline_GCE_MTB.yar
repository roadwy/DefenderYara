
rule Trojan_BAT_Redline_GCE_MTB{
	meta:
		description = "Trojan:BAT/Redline.GCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 00 06 18 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 6f 90 01 03 0a 0b 02 28 90 01 03 0a 0c 07 08 16 08 8e 69 6f 90 01 03 0a 0d 09 13 04 de 0b 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {4a 00 6e 00 50 00 45 00 48 00 7a 00 2f 00 61 00 43 00 52 00 46 00 79 00 73 00 2b 00 74 00 61 00 46 00 34 00 58 00 66 00 31 00 51 00 3d 00 3d 00 } //01 00  JnPEHz/aCRFys+taF4Xf1Q==
		$a_01_3 = {31 00 34 00 2b 00 4a 00 68 00 54 00 58 00 55 00 72 00 4c 00 68 00 5a 00 42 00 77 00 35 00 46 00 2b 00 32 00 6b 00 76 00 55 00 51 00 3d 00 3d 00 } //00 00  14+JhTXUrLhZBw5F+2kvUQ==
	condition:
		any of ($a_*)
 
}