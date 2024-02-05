
rule Trojan_BAT_ClipBanker_QA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {fa 25 33 00 16 00 00 02 00 00 00 46 00 00 00 17 00 00 00 58 00 00 00 91 00 00 00 60 00 00 00 11 00 00 00 01 00 00 00 03 00 00 00 1a 00 00 00 01 00 00 00 03 00 00 00 01 00 00 00 03 00 00 00 0a 00 00 00 09 00 00 00 02 00 00 00 02 00 00 00 01 } //03 00 
		$a_80_1 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //add_AssemblyResolve  03 00 
		$a_80_2 = {67 65 74 5f 49 73 41 6c 69 76 65 } //get_IsAlive  03 00 
		$a_80_3 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 35 2e 30 } //Confuser.Core 1.5.0  03 00 
		$a_80_4 = {46 61 69 6c 46 61 73 74 } //FailFast  00 00 
	condition:
		any of ($a_*)
 
}