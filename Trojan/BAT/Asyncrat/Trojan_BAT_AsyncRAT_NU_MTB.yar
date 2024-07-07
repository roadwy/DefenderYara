
rule Trojan_BAT_AsyncRAT_NU_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 b8 00 00 00 20 90 01 03 00 59 fe 90 01 02 00 20 90 01 03 00 38 90 01 03 00 11 11 11 10 11 01 38 90 01 03 00 13 04 20 90 01 03 00 fe 90 01 02 00 38 90 01 03 00 90 00 } //5
		$a_01_1 = {47 00 65 00 6e 00 65 00 72 00 61 00 6c 00 46 00 69 00 6c 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 GeneralFile.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}