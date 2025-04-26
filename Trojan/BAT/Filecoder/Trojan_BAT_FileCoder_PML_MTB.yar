
rule Trojan_BAT_FileCoder_PML_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.PML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0c 9a 6f ?? 00 00 0a 72 0e 07 00 70 28 ?? 00 00 0a 39 cc 00 00 00 11 06 11 0c 9a 6f ?? 00 00 0a 13 0d 11 0d 28 ?? 00 00 0a 26 11 06 11 0c 9a 6f ?? 00 00 0a 13 0e } //3
		$a_03_1 = {72 24 07 00 70 28 ?? 00 00 0a 2c 47 11 0d 11 07 72 20 07 00 70 11 06 11 0c 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 09 72 f8 06 00 70 28 3f 00 00 0a 11 0e 72 20 07 00 70 11 0f 72 0e 07 00 70 28 51 00 00 0a 28 52 00 00 0a 11 0d } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}