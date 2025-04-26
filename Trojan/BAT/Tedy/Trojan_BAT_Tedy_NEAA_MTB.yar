
rule Trojan_BAT_Tedy_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 2d f0 16 2d cd 1b 2c ea 2a 28 5f 00 00 0a 2b d4 28 41 00 00 0a 2b d9 28 0d 00 00 0a 2b d6 6f 60 00 00 0a 2b d1 6f 61 00 00 0a 2b ce } //10
		$a_01_1 = {4f 6e 53 74 65 61 6c 65 72 } //5 OnStealer
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}