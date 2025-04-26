
rule Trojan_BAT_Webshell_MBS_MTB{
	meta:
		description = "Trojan:BAT/Webshell.MBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 a0 03 00 00 95 5f 7e 36 00 00 04 20 f2 01 00 00 95 61 58 81 07 00 00 01 11 28 18 95 7e 36 00 00 04 1f 67 } //1
		$a_01_1 = {17 59 11 20 20 72 06 00 00 95 5f 11 20 20 9e 0d 00 00 95 61 58 80 1b 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}