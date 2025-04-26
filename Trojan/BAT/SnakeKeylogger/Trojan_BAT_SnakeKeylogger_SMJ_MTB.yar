
rule Trojan_BAT_SnakeKeylogger_SMJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 02 06 07 6f bb 00 00 0a 0c 04 03 6f bc 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 05 11 05 2c 2f 00 03 19 8d 8f 00 00 01 25 16 12 02 28 bd 00 00 0a 9c 25 17 12 02 28 be 00 00 0a 9c 25 18 12 02 28 bf 00 00 0a 9c 6f c0 00 00 0a 00 00 2b 4c 09 16 fe 02 13 06 11 06 2c 42 } //1
		$a_81_1 = {41 67 72 6f 46 61 72 6d 2e 57 61 72 65 68 6f 75 73 65 53 74 61 74 75 73 52 65 70 6f 72 74 2e 72 65 73 6f 75 72 63 65 73 } //1 AgroFarm.WarehouseStatusReport.resources
		$a_81_2 = {24 36 62 65 62 64 35 61 63 2d 61 37 32 63 2d 34 34 62 38 2d 61 37 64 39 2d 66 30 31 63 32 61 65 37 35 36 33 35 } //1 $6bebd5ac-a72c-44b8-a7d9-f01c2ae75635
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}