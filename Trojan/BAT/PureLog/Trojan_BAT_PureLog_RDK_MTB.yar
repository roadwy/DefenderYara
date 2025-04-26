
rule Trojan_BAT_PureLog_RDK_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 61 30 64 32 34 65 31 2d 31 32 31 62 2d 34 36 38 30 2d 38 65 65 37 2d 34 33 30 61 37 35 38 64 32 30 64 62 } //1 0a0d24e1-121b-4680-8ee7-430a758d20db
		$a_01_1 = {07 09 18 6f 10 00 00 0a 1f 10 28 11 00 00 0a 13 04 11 04 16 25 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}