
rule Trojan_BAT_Zilla_RR_MTB{
	meta:
		description = "Trojan:BAT/Zilla.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 19 11 1a 58 61 11 34 61 d2 9c 11 29 13 1a 17 11 0a 58 13 0a 11 0a 11 2a 32 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Zilla_RR_MTB_2{
	meta:
		description = "Trojan:BAT/Zilla.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 9a 0c 00 08 03 6f fc 06 00 0a 6f 05 07 00 0a 0d 09 2c 0c 00 7e 7b 0d 00 04 13 04 2b 4f } //1
		$a_01_1 = {77 6f 77 65 72 43 6c 69 65 6e 74 2e 65 78 65 } //1 wowerClient.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}