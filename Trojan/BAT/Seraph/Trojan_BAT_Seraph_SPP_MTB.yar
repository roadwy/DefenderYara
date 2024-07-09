
rule Trojan_BAT_Seraph_SPP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 1a 58 4a 9a 09 28 ?? ?? ?? 0a 2c 13 16 3a 45 ff ff ff 11 04 06 1a 58 4a 17 58 9a 13 05 2b 16 } //4
		$a_01_1 = {44 00 65 00 65 00 75 00 6c 00 62 00 77 00 6a 00 63 00 76 00 2e 00 57 00 64 00 77 00 6b 00 78 00 65 00 79 00 61 00 71 00 61 00 75 00 6c 00 63 00 6a 00 69 00 79 00 64 00 6f 00 77 00 7a 00 65 00 71 00 } //1 Deeulbwjcv.Wdwkxeyaqaulcjiydowzeq
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}