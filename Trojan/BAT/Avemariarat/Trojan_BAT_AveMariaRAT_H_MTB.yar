
rule Trojan_BAT_AveMariaRAT_H_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 11 07 6f 90 01 01 00 00 0a 13 08 08 12 08 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 07 17 58 13 07 11 07 07 6f 30 00 00 0a 32 90 01 01 11 06 17 58 13 06 11 06 07 6f 90 00 } //2
		$a_01_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}