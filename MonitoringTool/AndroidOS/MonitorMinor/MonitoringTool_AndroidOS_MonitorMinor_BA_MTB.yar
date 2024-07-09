
rule MonitoringTool_AndroidOS_MonitorMinor_BA_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MonitorMinor.BA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 65 6e 63 72 79 70 74 69 74 61 3b 6a 6c 6b 66 64 73 61 3b 66 64 6c 6b 6a } //1 _encryptita;jlkfdsa;fdlkj
		$a_03_1 = {0c 06 22 07 ?? ?? 70 10 ?? ?? 07 00 6e 20 ?? ?? 47 00 0c 07 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 07 00 0c 07 70 30 ?? ?? 65 07 6e 10 ?? ?? 05 00 0a 06 38 06 0c 00 6e 10 ?? ?? 05 00 0b 06 16 08 00 00 31 06 06 08 } //1
		$a_03_2 = {0c 06 6e 20 ?? ?? 46 00 0c 06 22 07 ?? ?? 70 10 ?? ?? 07 00 6e 20 ?? ?? 47 00 0c 04 1a 07 ?? ?? 6e 20 ?? ?? 74 00 0c 04 6e 10 ?? ?? 04 00 0c 04 71 30 ?? ?? 56 04 6e 10 ?? ?? 05 00 0c 04 71 10 ?? ?? 04 00 12 14 6a 04 ?? ?? 71 20 ?? ?? ba 00 0c 00 11 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}