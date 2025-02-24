
rule Trojan_BAT_ZemsilF_NF_MTB{
	meta:
		description = "Trojan:BAT/ZemsilF.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 59 00 00 0a 0a 06 6f ?? 00 00 0a 16 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 72 31 01 00 70 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 17 6f ?? 00 00 0a 00 72 31 01 00 70 28 4d 00 00 0a 26 2a } //3
		$a_01_1 = {02 6f 37 00 00 06 6f 4e 00 00 0a 00 72 f7 00 00 70 0a 06 28 4d 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}