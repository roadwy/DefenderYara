
rule Trojan_BAT_RedLine_KAT_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 4f 6b 51 72 62 70 65 42 56 2e 64 6c 6c } //rOkQrbpeBV.dll  1
		$a_80_1 = {67 5a 4c 6f 71 50 52 62 63 79 76 73 43 2e 64 6c 6c } //gZLoqPRbcyvsC.dll  1
		$a_80_2 = {6f 7a 4a 58 43 55 50 48 64 74 72 6d 51 2e 64 6c 6c } //ozJXCUPHdtrmQ.dll  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}