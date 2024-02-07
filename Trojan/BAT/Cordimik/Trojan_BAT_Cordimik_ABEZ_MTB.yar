
rule Trojan_BAT_Cordimik_ABEZ_MTB{
	meta:
		description = "Trojan:BAT/Cordimik.ABEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 07 16 73 90 01 03 0a 0c 73 90 01 03 0a 0d 08 09 6f 90 01 03 0a 04 09 6f 90 01 03 0a 51 de 1e 09 2c 06 09 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_2 = {4e 65 62 53 74 75 62 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //00 00  NebStub.Form1.resources
	condition:
		any of ($a_*)
 
}