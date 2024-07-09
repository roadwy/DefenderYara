
rule Trojan_BAT_Heracles_NHJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 1a 00 00 0a 0b 06 07 6f ?? 00 00 0a 0c 02 8e 69 8d ?? 00 00 01 0d 08 02 16 02 8e 69 09 16 6f ?? 00 00 0a } //5
		$a_01_1 = {57 65 62 5f 42 72 6f 77 73 65 72 2e 46 6f 72 6d 32 2e 72 65 73 6f 75 72 63 65 73 } //1 Web_Browser.Form2.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}