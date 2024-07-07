
rule Backdoor_BAT_WebShell_GMZ_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 19 9a 17 28 90 01 03 0a 0b 26 28 90 01 03 0a 26 02 6f 90 01 03 0a 28 90 01 03 0a 74 90 01 04 7b 90 01 04 25 16 03 a2 25 17 04 a2 25 18 06 a2 25 19 07 a2 26 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}