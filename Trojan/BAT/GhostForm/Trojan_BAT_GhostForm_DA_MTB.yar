
rule Trojan_BAT_GhostForm_DA_MTB{
	meta:
		description = "Trojan:BAT/GhostForm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 91 1f 10 62 02 07 17 58 91 1e 62 60 02 07 18 58 91 60 13 04 06 11 04 1f 12 63 1f 3f 5f 28 ?? 00 00 06 6f ?? 00 00 0a 26 06 11 04 1f 0c 63 1f 3f 5f } //10
		$a_03_1 = {02 07 91 1f 10 62 02 07 17 58 91 1e 62 60 02 07 18 58 91 60 0d 06 09 1f 12 63 1f 3f 5f 28 ?? 00 00 06 6f ?? 00 00 0a 26 06 09 1f 0c 63 1f 3f 5f } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}