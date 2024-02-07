
rule VirTool_BAT_CeeInject_DS_bit{
	meta:
		description = "VirTool:BAT/CeeInject.DS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3e 6a ff ff ff 2b 3c 11 90 02 02 1f 25 6f 90 02 02 00 00 0a 11 90 02 02 1f 0d 6f 90 02 02 00 00 0a 11 90 02 02 20 87 00 00 00 6f 90 02 02 00 00 0a 11 90 02 02 1f 41 90 00 } //01 00 
		$a_03_1 = {11 21 74 14 00 00 01 11 22 14 72 90 02 02 00 00 70 16 8d 01 00 00 01 14 14 14 28 0d 00 00 0a 74 15 00 00 01 17 73 15 00 00 0a 13 31 90 00 } //01 00 
		$a_01_2 = {52 61 00 53 61 6e 70 65 69 00 4f 72 61 63 6c 65 00 56 4e 43 } //00 00  慒匀湡数i牏捡敬嘀䍎
	condition:
		any of ($a_*)
 
}