
rule Trojan_BAT_Tnega_HXS_MTB{
	meta:
		description = "Trojan:BAT/Tnega.HXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 65 6c 6c 4d 61 6e 61 67 65 72 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //5 CellManager.g.resources
		$a_81_1 = {43 65 6c 6c 4d 61 6e 61 67 65 72 2e 65 78 65 } //5 CellManager.exe
		$a_81_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //5 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_81_3 = {47 6f 6f 67 6c 65 20 4c 4c 43 } //1 Google LLC
		$a_81_4 = {44 69 73 63 6f 72 64 20 49 6e 63 } //1 Discord Inc
		$a_81_5 = {31 31 31 31 31 2d 32 32 32 32 32 2d 31 30 30 30 39 2d 31 31 31 31 32 } //5 11111-22222-10009-11112
		$a_81_6 = {31 31 31 31 31 2d 32 32 32 32 32 2d 35 30 30 30 31 2d 30 30 30 30 32 } //5 11111-22222-50001-00002
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*5+(#a_81_6  & 1)*5) >=26
 
}