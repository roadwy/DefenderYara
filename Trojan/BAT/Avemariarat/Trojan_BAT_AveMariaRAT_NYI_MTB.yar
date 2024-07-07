
rule Trojan_BAT_AveMariaRAT_NYI_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 52 52 52 4d 52 52 52 52 65 52 52 52 52 74 52 52 52 52 68 52 52 52 52 6f 52 52 52 52 64 52 52 52 52 30 52 52 52 52 } //1 RRRRMRRRReRRRRtRRRRhRRRRoRRRRdRRRR0RRRR
		$a_81_1 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 00 00 4f 52 00 52 } //1
		$a_81_2 = {53 6e 69 70 65 52 } //1 SnipeR
		$a_81_3 = {6e 6e 71 38 6d 64 61 6f 69 75 73 6e 75 61 64 36 37 38 } //1 nnq8mdaoiusnuad678
		$a_81_4 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //1 GetManifestResourceNames
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}