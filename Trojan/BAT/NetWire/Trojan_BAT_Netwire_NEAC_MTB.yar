
rule Trojan_BAT_Netwire_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Netwire.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1f 09 11 04 18 5b 07 11 04 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 16 2d 06 11 04 18 58 13 04 16 2d ba 11 04 08 32 d9 90 00 } //10
		$a_01_1 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73 } //5 SmartAssembly.Attributes
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}