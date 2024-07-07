
rule Trojan_BAT_Neshta_AACX_MTB{
	meta:
		description = "Trojan:BAT/Neshta.AACX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 8e 69 17 da 13 08 16 13 09 2b 1b 11 04 11 09 09 11 09 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 09 17 d6 13 09 11 09 11 08 31 df 90 00 } //4
		$a_01_1 = {50 00 6f 00 6c 00 6c 00 69 00 6e 00 67 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //1 Polling_Project
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}