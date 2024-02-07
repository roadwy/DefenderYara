
rule VirTool_BAT_Cajan_A_MTB{
	meta:
		description = "VirTool:BAT/Cajan.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_81_0 = {77 69 6e 70 65 61 73 } //01 00  winpeas
		$a_81_1 = {53 33 63 75 72 33 54 68 31 73 53 68 31 74 2f 53 68 61 72 70 42 79 65 42 65 61 72 } //01 00  S3cur3Th1sSh1t/SharpByeBear
		$a_81_2 = {43 56 45 5f 32 30 31 39 5f 31 34 30 35 } //00 00  CVE_2019_1405
	condition:
		any of ($a_*)
 
}