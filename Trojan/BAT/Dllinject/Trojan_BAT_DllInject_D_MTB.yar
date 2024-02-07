
rule Trojan_BAT_DllInject_D_MTB{
	meta:
		description = "Trojan:BAT/DllInject.D!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 00 74 00 4f 00 33 00 4e 00 74 00 62 00 32 00 74 00 6c 00 64 00 47 00 56 00 7a 00 64 00 41 00 3d 00 3d 00 } //01 00  ZtO3Ntb2tldGVzdA==
		$a_01_1 = {41 00 6e 00 64 00 72 00 6f 00 69 00 64 00 53 00 74 00 75 00 64 00 69 00 6f 00 } //00 00  AndroidStudio
	condition:
		any of ($a_*)
 
}