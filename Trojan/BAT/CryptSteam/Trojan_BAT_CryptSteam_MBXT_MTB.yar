
rule Trojan_BAT_CryptSteam_MBXT_MTB{
	meta:
		description = "Trojan:BAT/CryptSteam.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 ea e0 00 00 28 66 7f 00 06 13 12 20 0b 00 00 00 38 7a 01 00 00 1f 35 13 43 20 22 00 00 00 17 } //3
		$a_01_1 = {56 69 44 65 6f 41 75 74 6f 52 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //2 ViDeoAutoR.Resources.resource
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}