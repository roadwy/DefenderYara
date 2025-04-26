
rule Trojan_BAT_ZillaCrypt_NMA_MTB{
	meta:
		description = "Trojan:BAT/ZillaCrypt.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {38 65 33 39 30 34 39 39 2d 32 33 66 37 2d 34 39 63 30 2d 39 61 64 66 2d 34 33 64 65 64 63 61 62 39 62 39 32 } //2 8e390499-23f7-49c0-9adf-43dedcab9b92
		$a_01_1 = {11 31 11 0e 46 11 21 61 52 11 0e 17 58 13 0e 11 31 17 58 13 31 2b e2 } //2
		$a_01_2 = {e0 4a 11 08 11 11 17 59 8f c3 00 00 01 e0 4a 61 54 11 0f 11 11 18 59 16 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}