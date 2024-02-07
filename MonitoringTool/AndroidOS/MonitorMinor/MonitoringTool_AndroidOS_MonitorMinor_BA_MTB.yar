
rule MonitoringTool_AndroidOS_MonitorMinor_BA_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MonitorMinor.BA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 65 6e 63 72 79 70 74 69 74 61 3b 6a 6c 6b 66 64 73 61 3b 66 64 6c 6b 6a } //01 00  _encryptita;jlkfdsa;fdlkj
		$a_03_1 = {0c 06 22 07 90 01 02 70 10 90 01 02 07 00 6e 20 90 01 02 47 00 0c 07 1a 08 90 01 02 6e 20 90 01 02 87 00 0c 07 6e 10 90 01 02 07 00 0c 07 70 30 90 01 02 65 07 6e 10 90 01 02 05 00 0a 06 38 06 0c 00 6e 10 90 01 02 05 00 0b 06 16 08 00 00 31 06 06 08 90 00 } //01 00 
		$a_03_2 = {0c 06 6e 20 90 01 02 46 00 0c 06 22 07 90 01 02 70 10 90 01 02 07 00 6e 20 90 01 02 47 00 0c 04 1a 07 90 01 02 6e 20 90 01 02 74 00 0c 04 6e 10 90 01 02 04 00 0c 04 71 30 90 01 02 56 04 6e 10 90 01 02 05 00 0c 04 71 10 90 01 02 04 00 12 14 6a 04 90 01 02 71 20 90 01 02 ba 00 0c 00 11 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}