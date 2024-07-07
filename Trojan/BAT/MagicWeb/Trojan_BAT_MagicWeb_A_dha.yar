
rule Trojan_BAT_MagicWeb_A_dha{
	meta:
		description = "Trojan:BAT/MagicWeb.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 8f 60 00 00 01 72 a3 04 00 70 28 } //1
		$a_01_1 = {28 62 00 00 0a 6f 63 00 00 0a 26 11 04 17 58 13 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}