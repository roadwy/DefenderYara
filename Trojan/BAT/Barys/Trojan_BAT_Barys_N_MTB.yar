
rule Trojan_BAT_Barys_N_MTB{
	meta:
		description = "Trojan:BAT/Barys.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {1f 09 11 07 1f 09 95 08 1f 09 95 61 9e 11 07 1f 0a 11 07 1f 0a 95 08 1f 0a 95 61 9e 11 0c 20 e2 e4 c7 d2 5a 20 c4 9a 28 30 61 38 b9 fc ff ff } //05 00 
		$a_01_1 = {16 11 07 16 95 08 16 95 61 9e 11 07 17 11 07 17 95 08 17 95 61 9e 11 0c 20 f9 99 00 7a 5a 20 6f a4 20 6e 61 38 ea fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}