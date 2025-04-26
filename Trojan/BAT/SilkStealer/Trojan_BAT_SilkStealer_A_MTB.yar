
rule Trojan_BAT_SilkStealer_A_MTB{
	meta:
		description = "Trojan:BAT/SilkStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 69 6c 6b 2e 70 64 62 } //2 Silk.pdb
		$a_01_1 = {4d 6f 7a 47 6c 75 65 4e 6f 74 46 6f 75 6e 64 } //2 MozGlueNotFound
		$a_01_2 = {4e 73 73 33 43 6f 75 6c 64 4e 6f 74 42 65 4c 6f 61 64 65 64 } //2 Nss3CouldNotBeLoaded
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}