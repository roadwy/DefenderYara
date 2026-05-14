
rule Trojan_BAT_MaskGramStealer_AMR_MTB{
	meta:
		description = "Trojan:BAT/MaskGramStealer.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 06 6f ?? 00 00 0a 00 11 05 07 6f ?? 00 00 0a 00 11 05 17 6f ?? 00 00 0a 00 11 05 17 6f ?? 00 00 0a 00 11 05 16 6f ?? 00 00 0a 00 11 05 0c 08 28 ?? 00 00 0a 0d 00 09 14 fe 01 16 fe 01 13 07 11 07 2d 05 1e 13 06 } //2
		$a_01_1 = {63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 63 00 66 00 67 00 } //1 config.cfg
		$a_01_2 = {4e 00 6f 00 6c 00 6f 00 67 00 6f 00 } //1 Nologo
		$a_01_3 = {45 00 3a 00 56 00 42 00 53 00 63 00 72 00 69 00 70 00 74 00 } //1 E:VBScript
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}