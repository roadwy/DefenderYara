
rule Trojan_BAT_Taskun_ARAG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 74 ce 03 70 72 78 ce 03 70 6f 53 00 00 0a 72 7e ce 03 70 72 01 00 00 70 } //02 00 
		$a_03_1 = {11 04 11 09 18 6f 90 01 03 0a 13 0a 11 05 11 09 18 5b 11 0a 1f 10 28 90 01 03 0a d2 9c 00 11 09 18 58 13 09 11 09 11 04 6f 90 01 03 0a fe 04 13 0b 11 0b 2d ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}