
rule Trojan_BAT_Redline_SK_MTB{
	meta:
		description = "Trojan:BAT/Redline.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 64 6f 77 73 20 50 65 72 66 20 42 6f 6f 73 74 65 72 } //1 Windows Perf Booster
		$a_81_1 = {48 79 64 61 74 69 64 73 2e 65 78 65 } //1 Hydatids.exe
		$a_81_2 = {47 65 61 72 55 70 20 43 6f 72 70 6f 72 61 74 69 6f 6e 20 43 6f 70 79 72 69 67 68 74 } //1 GearUp Corporation Copyright
		$a_81_3 = {46 70 73 20 62 6f 6f 73 74 65 72 } //1 Fps booster
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}