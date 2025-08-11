
rule Trojan_BAT_Heracles_MBX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_1 = {53 00 65 00 6e 00 69 00 6f 00 72 00 00 11 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 00 0f 4c 00 20 00 6f 00 20 00 61 00 20 00 64 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}
rule Trojan_BAT_Heracles_MBX_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.MBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 04 1c d6 5d 8c ?? 00 00 01 02 28 ?? 00 00 06 14 04 1c ?? ?? ?? ?? ?? 28 ?? 00 00 06 17 8d ?? 00 00 01 25 16 03 8c ?? 00 00 01 a2 25 0b 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0c } //5
		$a_01_1 = {79 30 4a 59 73 39 64 31 44 32 4c 62 51 67 37 33 48 71 65 36 4b 41 6b 35 38 52 6e 61 34 53 35 4d } //5 y0JYs9d1D2LbQg73Hqe6KAk58Rna4S5M
		$a_01_2 = {6b 39 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 k9.Resources.resources
		$a_01_3 = {44 61 74 61 20 45 6e 63 6f 64 65 72 20 43 72 79 70 74 65 72 } //1 Data Encoder Crypter
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}