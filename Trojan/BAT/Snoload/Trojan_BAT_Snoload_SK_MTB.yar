
rule Trojan_BAT_Snoload_SK_MTB{
	meta:
		description = "Trojan:BAT/Snoload.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 19 00 00 0a 0b 07 72 01 00 00 70 6f 1a 00 00 0a 0a de 0a 07 2c 06 07 6f 1b 00 00 0a dc } //2
		$a_01_1 = {44 6f 77 6e 4c 6f 61 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 DownLoader.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}