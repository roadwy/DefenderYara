
rule Trojan_BAT_Nanocore_NNE_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 5b 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f ?? 00 00 0a 25 26 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a } //5
		$a_01_1 = {4e 4e 6e 48 37 36 } //1 NNnH76
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}