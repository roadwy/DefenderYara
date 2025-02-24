
rule Backdoor_BAT_Remcos_KABB_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 03 19 8d ?? 00 00 01 25 16 11 13 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 13 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 13 20 ff 00 00 00 5f d2 9c } //1
		$a_03_1 = {13 18 03 19 8d ?? 00 00 01 25 16 12 0d 28 ?? 00 00 0a 9c 25 17 12 0d 28 ?? 00 00 0a 9c 25 18 12 0d 28 ?? 00 00 0a 9c 11 0e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}