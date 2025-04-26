
rule TrojanSpy_BAT_Noon_SKK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 91 07 28 24 00 00 06 2c 0c 06 08 8f 44 00 00 01 28 25 00 00 06 04 06 08 91 6f 38 00 00 0a 08 17 58 0c 08 03 32 d8 } //2
		$a_81_1 = {47 6d 61 2e 55 73 65 72 41 63 74 69 76 69 74 79 4d 6f 6e 69 74 6f 72 44 65 6d 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Gma.UserActivityMonitorDemo.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}