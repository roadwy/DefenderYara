
rule Trojan_BAT_Lokibot_ABVF_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 01 00 00 0a 08 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 14 17 8d 90 01 01 00 00 01 25 16 07 a2 6f 90 01 01 00 00 0a 75 90 01 01 00 00 1b 08 28 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 2a 90 00 } //4
		$a_01_1 = {31 00 39 00 32 00 2e 00 32 00 33 00 36 00 2e 00 31 00 39 00 32 00 2e 00 36 00 31 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}