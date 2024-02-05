
rule Backdoor_BAT_Evilnum_SP_MTB{
	meta:
		description = "Backdoor:BAT/Evilnum.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {09 08 6f 1d 00 00 0a 6f 0a 00 00 0a 26 11 04 6f 1e 00 00 0a 09 6f 0b 00 00 0a 09 16 09 6f 1f 00 00 0a 6f 20 00 00 0a 26 38 d3 ff ff ff } //03 00 
		$a_81_1 = {44 61 74 61 52 65 63 65 69 76 65 64 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}