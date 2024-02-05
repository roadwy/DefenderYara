
rule Trojan_BAT_ClipBanker_NH_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {17 00 00 00 b8 00 00 00 07 00 00 00 04 00 00 00 6b 00 00 00 16 00 00 00 41 00 00 00 77 00 00 00 12 00 00 00 03 00 00 00 2a 00 00 00 0f 00 00 00 } //01 00 
		$a_01_1 = {57 bf a2 3f 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 a6 00 00 00 52 00 00 00 07 01 00 00 a7 01 00 00 43 01 00 00 03 00 00 00 cc 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}