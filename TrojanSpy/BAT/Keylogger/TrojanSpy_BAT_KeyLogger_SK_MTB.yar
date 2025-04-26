
rule TrojanSpy_BAT_KeyLogger_SK_MTB{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 00 04 00 00 5b 20 00 04 00 00 5b 1f 64 5a 1f 18 5b 0d 09 18 31 07 02 09 28 0d 00 00 06 07 17 58 0b 07 06 8e 69 32 a7 } //2
		$a_81_1 = {53 66 6b 4c 6f 61 64 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 SfkLoader.Form1.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}