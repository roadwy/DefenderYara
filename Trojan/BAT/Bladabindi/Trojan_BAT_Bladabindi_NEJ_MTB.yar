
rule Trojan_BAT_Bladabindi_NEJ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 02 1f 0c 11 04 16 09 28 bd 00 00 0a 12 04 09 28 04 00 00 2b 06 07 08 28 b9 00 00 0a 11 04 6f be 00 00 0a 73 4b 00 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}