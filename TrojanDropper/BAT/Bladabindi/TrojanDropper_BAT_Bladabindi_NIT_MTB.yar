
rule TrojanDropper_BAT_Bladabindi_NIT_MTB{
	meta:
		description = "TrojanDropper:BAT/Bladabindi.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 07 6f ?? 00 00 0a 0c 08 6f ?? 00 00 0a 13 05 11 05 2c 29 07 06 fe 01 16 fe 01 13 06 11 06 2c 17 7e 01 00 00 04 06 7e 01 00 00 04 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 00 06 17 58 0a 00 00 07 17 58 0b 07 11 04 13 07 11 07 31 b0 } //2
		$a_01_1 = {5c 6f 62 6a 5c 44 65 62 75 67 5c 53 6f 66 74 77 61 72 65 2e 70 64 62 } //1 \obj\Debug\Software.pdb
		$a_01_2 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //1 GetResourceString
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}