
rule Trojan_BAT_AgentTesla_EKV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 ?? ?? ?? 06 20 9e 02 00 00 da 13 05 11 05 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 06 07 11 06 28 ?? ?? ?? 06 0b 00 09 17 d6 0d 09 08 28 ?? ?? ?? 06 fe 04 13 07 11 07 2d b8 90 09 0c 00 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 } //1
		$a_01_1 = {00 47 65 74 54 79 70 65 } //1 䜀瑥祔数
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_EKV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 00 42 00 42 00 45 00 45 00 4b 00 67 00 49 00 47 00 49 00 46 00 31 00 42 00 77 00 28 06 27 06 78 00 68 00 42 00 31 00 68 00 68 00 43 00 57 00 45 00 54 00 45 00 68 00 45 00 53 00 42 00 69 00 43 00 43 00 57 00 } //1 TBBEEKgIGIF1BwباxhB1hhCWETEhESBiCCW
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //1 System.Convert
		$a_01_2 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
		$a_01_3 = {53 00 68 00 61 00 72 00 70 00 53 00 74 00 72 00 75 00 63 00 74 00 75 00 72 00 65 00 73 00 2e 00 4d 00 61 00 69 00 6e 00 2e 00 53 00 6f 00 72 00 74 00 48 00 65 00 6c 00 70 00 65 00 72 00 } //1 SharpStructures.Main.SortHelper
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}