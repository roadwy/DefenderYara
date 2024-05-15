
rule Trojan_BAT_RedLine_RDER_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 67 65 78 43 6f 6e 74 69 6e 75 65 50 61 72 73 69 6e 67 } //01 00  RegexContinueParsing
		$a_01_1 = {55 6e 77 69 6e 64 53 69 7a 65 50 61 72 61 6d 49 6e 64 65 78 } //01 00  UnwindSizeParamIndex
		$a_01_2 = {46 72 6f 6d 45 6e 64 4d 6f 6e 74 68 45 6e 64 } //00 00  FromEndMonthEnd
	condition:
		any of ($a_*)
 
}