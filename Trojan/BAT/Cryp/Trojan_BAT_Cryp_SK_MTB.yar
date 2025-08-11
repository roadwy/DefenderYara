
rule Trojan_BAT_Cryp_SK_MTB{
	meta:
		description = "Trojan:BAT/Cryp.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 d6 0b 09 0c 07 0d 11 0f 17 d6 13 0f 11 0f 1f 5a 31 ec } //2
		$a_81_1 = {46 61 62 74 6f 6d 50 61 72 64 2e 52 65 73 6f 75 72 63 65 73 } //2 FabtomPard.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}