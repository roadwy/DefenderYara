
rule TrojanDropper_BAT_VB_G{
	meta:
		description = "TrojanDropper:BAT/VB.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 5f 73 75 62 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 crypt_sub.Resources.resources
		$a_01_1 = {43 6f 79 6e 65 79 27 73 20 43 72 79 70 74 65 72 5c 63 72 79 70 74 20 73 75 62 5c } //1 Coyney's Crypter\crypt sub\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}