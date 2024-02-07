
rule Trojan_BAT_Tnega_AM_MTB{
	meta:
		description = "Trojan:BAT/Tnega.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 65 72 } //01 00  Crypter
		$a_01_1 = {6c 69 6e 6b 78 6d 72 } //01 00  linkxmr
		$a_01_2 = {73 65 74 5f 53 68 6f 77 49 6e 54 61 73 6b 62 61 72 } //01 00  set_ShowInTaskbar
		$a_01_3 = {52 4e 47 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  RNGCryptoServiceProvider
		$a_01_4 = {54 61 73 6b 32 34 4d 61 69 6e 2e 70 64 62 } //01 00  Task24Main.pdb
		$a_01_5 = {6d 63 6f 6e 68 6f 73 74 } //00 00  mconhost
	condition:
		any of ($a_*)
 
}