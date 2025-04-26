
rule Backdoor_BAT_Androm_EAN_MTB{
	meta:
		description = "Backdoor:BAT/Androm.EAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 73 10 00 00 06 25 07 28 ?? 00 00 06 6f ?? 00 00 06 0c dd ?? 00 00 00 26 de c9 } //2
		$a_01_1 = {63 00 6f 00 6e 00 76 00 2e 00 6f 00 76 00 66 00 2e 00 75 00 34 00 } //1 conv.ovf.u4
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}